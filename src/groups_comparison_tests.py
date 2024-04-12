import ipaddress
import random
import argparse
import uuid
import math

groups_list = list()
size_map = dict()

class AddressGroup:
	def __init__(self, group_name):
		self.group_name = group_name
		self.members = list()
		self.ip_tuples = list()
		self.ip_count = 0

	def add_range(self, range):
		r = range
		if type(range) is not ipaddress.IPv4Network:
			r = ipaddress.ip_network(range, False)
		self.members.append(r)

		self.ip_tuples.append((int(r.network_address), int(r.broadcast_address)))

	def add_group(self, group):
		self.members.append(group)

	def merge_ip_tuples(self):
		merge_finished = False
		tuples_list = sorted(self.ip_tuples)
		merged_tuples = set()

		if len(self.ip_tuples) > 1:
			while not merge_finished:
				merged_tuples = set()
				merge_done = False
				last_loop_merged = False
				for tup_index in range(1, len(tuples_list)):
					if last_loop_merged:
						last_loop_merged = False
						continue
					if tuples_list[tup_index - 1][1] + 1 >= tuples_list[tup_index][0]:
						min_add = min(tuples_list[tup_index - 1][0], tuples_list[tup_index][0])
						max_add = max(tuples_list[tup_index - 1][1], tuples_list[tup_index][1])
						merged_tuples.add((min_add, max_add))
						#print(f"Merged {tuples_list[tup_index-1]} with {tuples_list[tup_index]} --> ({min_add},{max_add})")
						merge_done = True
						last_loop_merged = True
					else:
						merged_tuples.add(tuples_list[tup_index - 1])
						#print(f"Adding {tuples_list[tup_index-1]}")
						if tup_index + 1 == len(tuples_list):
							#print(f"Last index : adding {tuples_list[tup_index]}")
							merged_tuples.add(tuples_list[tup_index])
				merge_finished = True if not merge_done else False
				#print(f"merge_finished : {merge_finished} / merge_done : {merge_done}")
				tuples_list = list(sorted(merged_tuples))
				#print(tuples_list)
			self.ip_tuples = list(sorted(merged_tuples))
		self.ip_count = calc_group_size(self)

def cli_parse():
	parser = argparse.ArgumentParser()

	parser.add_argument(
		"--groups-count", 
		action = "store", 
		help = "Number of groups to generate", 
		required = True
	)

	parser.add_argument(
		"--max-network-per-group", 
		help = "Maximum number of networks to add to each group", 
		required=True
	)

	parser.add_argument(
		"--similarity-percent", 
		action = "store", 
		help = "Similarity level (%) accross groups to match", 
		required = True
	)

	parser.add_argument(
		"--groups-to-compare", 
		action = "store", 
		help = "Number of randomly selected groups to compare", 
		required = True
	)

	return parser.parse_args()

def compare_groups(g1, g2):
	i, j = 0, 0 
	intersect_nb = 0
	left_diff = 0
	right_diff = 0
	count_diff = 0

	while i < len(g1.ip_tuples) and j < len(g2.ip_tuples): 
		if g1.ip_tuples[i][1] >= g2.ip_tuples[j][0] and g2.ip_tuples[j][1] >= g1.ip_tuples[i][0]:
			print(f"Checking intersection between {ipaddress.IPv4Address(g1.ip_tuples[i][0])} -> {ipaddress.IPv4Address(g1.ip_tuples[i][1])} and {ipaddress.IPv4Address(g2.ip_tuples[j][0])} -> {ipaddress.IPv4Address(g2.ip_tuples[j][1])}")
			intersect_start = max(g1.ip_tuples[i][0], g2.ip_tuples[j][0])
			print(f"Intersect start : {ipaddress.IPv4Address(intersect_start)}")
			intersect_stop = min(g1.ip_tuples[i][1], g2.ip_tuples[j][1])
			print(f"Intersect stop : {ipaddress.IPv4Address(intersect_stop)}")
			intersect_nb += intersect_stop - intersect_start + 1

		if g1.ip_tuples[i][0] < g2.ip_tuples[j][0]:
			left_diff += g2.ip_tuples[j][0] - g1.ip_tuples[i][0]
			count_diff += g2.ip_tuples[j][0] - g1.ip_tuples[i][0]
			i += 1
		elif g2.ip_tuples[j][1] > g1.ip_tuples[i][0]:
			right_diff += g2.ip_tuples[j][1] - g1.ip_tuples[i][1]
			count_diff -= g2.ip_tuples[j][1] - g1.ip_tuples[i][1]
			j += 1
		else:
			i += 1
			j += 1

	while j < len(g2.ip_tuples):
		right_diff += g2.ip_tuples[j][1] - g1.ip_tuples[-1][1]
		count_diff -= g2.ip_tuples[j][1] - g1.ip_tuples[-1][1]
		j += 1
	print(f"G1 ip count : {g1.ip_count} / G2 ip count : {g2.ip_count}")
	percent_match = round(abs(intersect_nb) / (g1.ip_count + g2.ip_count - intersect_nb) * 100, 2) 
	return abs(intersect_nb), count_diff, left_diff, right_diff, percent_match


def generate_ip_range():
	rand_ip = '.'.join([str(random.randint(0,255)) for _ in range(4)])
	rand_network = str(random.randint(1,32))
	return f"{rand_ip}/{rand_network}"

def calc_group_size(group):
	size = 0
	for g in group.ip_tuples:
		size += g[1] - g[0]
	return size


def main():
	start_cli_args = cli_parse()

	print(f"Creating {start_cli_args.groups_count} groups with up to {start_cli_args.max_network_per_group} networks each")
	for _ in range(int(start_cli_args.groups_count)):
		g = AddressGroup(group_name = uuid.uuid1())
		for _ in range(int(start_cli_args.max_network_per_group)):
			net_r = ipaddress.ip_network(generate_ip_range(), False)
			if str(net_r.network_address) != "0.0.0.0":
				g.add_range(net_r)

		g.merge_ip_tuples()
		groups_list.append(g)

		total_size = g.ip_count
		if not total_size in size_map:
			size_map[total_size] = list()
		size_map[total_size].append(g)

	to_compare = list()
	for _ in range(int(start_cli_args.groups_to_compare)):
		to_compare.append(groups_list[random.randint(0, len(groups_list) - 1)])

	print("The following groups will be compared : ")
	for g in to_compare:
		g_size = calc_group_size(g)
		percent_diff = g_size * (int(start_cli_args.similarity_percent) / 100)
		min_compare_size = math.floor(g_size - percent_diff)
		max_compare_size = math.ceil(g_size + percent_diff)

		target_groups_list = list()
		any([target_groups_list.extend(y) for x,y in size_map.items() if x >= min_compare_size and x <= max_compare_size])
		print(f"{g.group_name} --> group size is {g_size} looking for groups sized between {min_compare_size} and {max_compare_size} ({len(target_groups_list)} groups matched)")

		best_match_group = None
		best_match = 0 
		best_left_group = None
		best_left_match = 0, 0
		best_right_group = None
		best_right_match = 0, 0

		for tg in target_groups_list:
			if tg != g:
				intersection, diff, left_diff, right_diff, percent_match = compare_groups(g, tg)
				print(f"{g.group_name} <--> {tg.group_name} : Intersection is {intersection}, diff is {diff}, L/R diff is {left_diff} / {right_diff}, match is {percent_match} %")
				if percent_match > best_match:
					best_match_group = tg
					best_match = percent_match
				if best_left_match[0] == 0 or (percent_match > best_left_match[1] and left_diff < best_left_match[0]):
					best_left_match = left_diff, percent_match
					best_left_group = tg
				if best_right_match[0] == 0 or (percent_match > best_right_match[1] and right_diff < best_right_match[0]):
					best_right_match = right_diff, percent_match
					best_right_group = tg

		print("\n\n")
		print(f"Best match for {g.group_name} : \n {sorted(g.members)}\n\n")
		if best_match_group:
			print(f"Global percent : {best_match_group.group_name} at {best_match} % : \n {sorted(best_match_group.members)}\n\n")
			print(f"Best left : {best_left_group.group_name} at ({best_left_match[0]} / {best_left_match[1]} %) : \n {sorted(best_left_group.members)}\n\n")
			print(f"Best right : {best_right_group.group_name} at ({best_right_match[0]} / {best_right_match[1]} %) : \n {sorted(best_right_group.members)}\n\n")
		else:
			print(f"NO MATCHING GROUP FOUND")
		print("\n\n")


if __name__ == "__main__":
	main()