import ipaddress
import random
import argparse
import uuid
import math
import time

groups_list = list()
size_map = dict()

class AddressGroup:
	def __init__(self, group_name):
		self.group_name = group_name
		self.members = list()
		self.ip_tuples = list()
		self.ip_count = 0
		self.max_ip = 0
		self.min_ip = None

	def add_range(self, range_in):
		r = range_in
		if type(range_in) is not ipaddress.IPv4Network:
			r = ipaddress.ip_network(range_in, False)
		self.members.append(r)

		self.ip_tuples.append((int(r.network_address), int(r.broadcast_address)))

		if int(r.broadcast_address) > self.max_ip:
			self.max_ip = int(r.broadcast_address)

		if not self.min_ip:
			self.min_ip = int(r.network_address)
		elif self.min_ip > int(r.network_address):
			self.min_ip = int(r.network_address)

	def add_group(self, group):
		self.members.append(group)

	def merge_ip_tuples(self):
		# this function merges contiguous IP ranges on the AddressGroup
		merge_finished = False
		tuples_list = sorted(self.ip_tuples)

		# if group size is not more than 1, no need to merge anything
		if len(self.ip_tuples) > 1:
			# loop while merges have been done on the previous iterations
			while not merge_finished:
				merged_tuples = set()
				#merge_done is moved to True as soon as 1 merging operation occurs in the current loop 
				merge_done = False
				last_loop_merged = False

				# looping on all groups member, from the second one (index=1) to the last one + 1 (len)
				for tup_index in range(1, len(tuples_list)):
					# if a merging operation has been done on the previous for loop iteration, ignore this one (groups are merged by pairs of 2)
					# except if we are on the last member if the group 
					if last_loop_merged:
						if tup_index + 1 == len(tuples_list):
							merged_tuples.add(tuples_list[tup_index])
						last_loop_merged = False
						continue

					# of tuple at current index - 1 and at current index can merge, find the intersection between both tuples and add it to the merged_tuples set 
					if tuples_list[tup_index - 1][1] + 1 >= tuples_list[tup_index][0]:
						min_add = min(tuples_list[tup_index - 1][0], tuples_list[tup_index][0])
						max_add = max(tuples_list[tup_index - 1][1], tuples_list[tup_index][1])
						#print(min_add)
						#print(max_add)
						merged_tuples.add((min_add, max_add))
						#print(f"Merged {ipaddress.ip_address(tuples_list[tup_index-1][0])} / {ipaddress.ip_address(tuples_list[tup_index-1][1])} with {ipaddress.ip_address(tuples_list[tup_index][0])} / {ipaddress.ip_address(tuples_list[tup_index][1])} --> ({ipaddress.ip_address(min_add)},{ipaddress.ip_address(max_add)})")
						merge_done = True
						last_loop_merged = True

					# else just add the tuple at current index - 1 to the merged_tuples set and move to the next for loop iteration 
					else:
						merged_tuples.add(tuples_list[tup_index - 1])
						#print(f"Adding {tuples_list[tup_index-1]}")

						# if we are at the last index of the group, add the lat member to the merged_tuples set 
						if tup_index + 1 == len(tuples_list):
							#print(f"Last index : adding {tuples_list[tup_index]}")
							merged_tuples.add(tuples_list[tup_index])

				# merge_finished is set to True if no merge has been processed on the last for loop (iteration over the full tuples set)
				merge_finished = True if not merge_done else False
				#print(f"merge_finished : {merge_finished} / merge_done : {merge_done}")
				tuples_list = list(sorted(merged_tuples)) if merge_done else tuples_list
				#print(tuples_list)
			self.ip_tuples = list(sorted(tuples_list))

		# once all ip_tuples have been merged, calculate the group size (number of IPs on the AddressGroup)
		self.ip_count = self.calc_group_size()

		#print("\n\n")
		#print(f"After merging, {self.group_name} is : ")
		#for tup_c in self.ip_tuples:
		#	print(f"  {ipaddress.ip_address(tup_c[0])} --> {ipaddress.ip_address(tup_c[1])}")

	def calc_group_size(self):
		size = 0
		for g in self.ip_tuples:
			size += g[1] - g[0] + 1
		return size


def compare_groups(g1, g2):
	i, j = 0, 0 
	intersect_nb = 0
	left_diff = 0
	right_diff = 0
	count_diff = 0
	last_comparison_step = min(g1.min_ip, g2.min_ip)
	#print(f"G1 min is {g1.min_ip}")
	#print(f"G2 min is {g2.min_ip}")

	while last_comparison_step <= max(g1.max_ip, g2.max_ip):
		#print(f"Last comparison step is {ipaddress.ip_address(last_comparison_step)}, i = {i}, j = {j}")
		#print(f"Left tuple is {g1.ip_tuples[i]}")
		#print(f"Right tuple is {g2.ip_tuples[j]}")
		left_active = i < len(g1.ip_tuples) and last_comparison_step >= g1.ip_tuples[i][0] and last_comparison_step <= g1.ip_tuples[i][1]
		right_active = j < len(g2.ip_tuples) and last_comparison_step >= g2.ip_tuples[j][0] and last_comparison_step <= g2.ip_tuples[j][1]
		#print(f"Left active : {left_active} / Right active : {right_active}")

		if left_active and right_active:
			# we are on an intersection range
			intersect_stop = min(g1.ip_tuples[i][1], g2.ip_tuples[j][1])
			intersect_nb += intersect_stop - last_comparison_step + 1
			last_comparison_step = intersect_stop + 1
			#print(f"End of intersection is {ipaddress.ip_address(last_comparison_step - 1)}, jumping to {ipaddress.ip_address(last_comparison_step)}")
			if last_comparison_step > g1.ip_tuples[i][1]:
				i += 1
				#print("Incremented i")
			if last_comparison_step > g2.ip_tuples[j][1]:
				j += 1
				#print("Incremented j")
		elif left_active:
			# adding to left diff
			if j < len(g2.ip_tuples):
				left_diff_stop = min(g1.ip_tuples[i][1], g2.ip_tuples[j][0] - 1)
			else:
				left_diff_stop = g1.ip_tuples[i][1]
			left_diff += left_diff_stop - last_comparison_step + 1
			last_comparison_step = left_diff_stop + 1
			#print(f"End of left is {ipaddress.ip_address(last_comparison_step - 1)}, jumping to {ipaddress.ip_address(last_comparison_step)}")
			if last_comparison_step > g1.ip_tuples[i][1]:
				i += 1
				#print("Incremented i")
		elif right_active:
			# adding to right diff
			if i < len(g1.ip_tuples):
				right_diff_stop = min(g2.ip_tuples[j][1], g1.ip_tuples[i][0] - 1)
			else:
				right_diff_stop = g2.ip_tuples[j][1]
			right_diff += right_diff_stop - last_comparison_step + 1
			last_comparison_step = right_diff_stop + 1
			#print(f"End of right is {ipaddress.ip_address(last_comparison_step - 1)}, jumping to {ipaddress.ip_address(last_comparison_step)}")
			if last_comparison_step > g2.ip_tuples[j][1]:
				j += 1
				#print("Incremented j")
		else:
			if i < len(g1.ip_tuples) and j < len(g2.ip_tuples):
				last_comparison_step = min(g1.ip_tuples[i][0], g2.ip_tuples[j][0])
				#print(f"No group active, jumping to next min for i and j : {last_comparison_step}")
			elif i < len(g1.ip_tuples):
				last_comparison_step = g1.ip_tuples[i][0]
				#print(f"j is over, jumping to next start value for i : {last_comparison_step}")
			else: 
				last_comparison_step = g2.ip_tuples[j][0]
				#print(f"i is over, jumping to next start value for j : {last_comparison_step}")

		#input("Press enter to continue")
		#print("\n\n")

	#print(f"G1 ip count : {g1.ip_count} / G2 ip count : {g2.ip_count}")

	# calculate the percent of match between G1 and G2 with the calculated values of intersect 
	percent_match = round(abs(intersect_nb) / (g1.ip_count + g2.ip_count - intersect_nb) * 100, 4) 

	return abs(intersect_nb), count_diff, abs(left_diff), abs(right_diff), percent_match

def generate_ip_range():
	# Generates random network values (network and subnet mask)
	rand_ip = '.'.join([str(random.randint(10,255)) for _ in range(4)])
	rand_network = str(random.randint(16,32))
	return f"{rand_ip}/{rand_network}"

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

	parser.add_argument(
		"--show-groups", 
		action = "store_true", 
		help = "Display groups content with results", 
		default = False
	)

	return parser.parse_args()



def main():
	# reading CLI arguments
	start_cli_args = cli_parse()

	print(f"Creating {start_cli_args.groups_count} groups with up to {start_cli_args.max_network_per_group} networks each")
	
	# creates groups_count groups. Each group is assigned a name value (generated uuid1 value)
	# and gets assigned max_network_per_group networks randomly generated by the generate_ip_range() function 
	for _ in range(int(start_cli_args.groups_count)):
		g = AddressGroup(group_name = uuid.uuid1())
		for _ in range(int(start_cli_args.max_network_per_group)):
			# using strict=False permits to create the network value even if host bits are set 
			while (net_r := ipaddress.ip_network(generate_ip_range(), strict=False)) == "0.0.0.0":
				continue
			g.add_range(net_r)


		# merging the generated AddressGroup ip_tuples (each representing the network and broadcast address of each member range)
		g.merge_ip_tuples()

		# add the new AddressGroup to the list of treated groups (groups_list)
		groups_list.append(g)

		# add the current group size (number of IPs) to the size_map dict (as a key), and the group itself as a value 
		if not g.ip_count in size_map:
			size_map[g.ip_count] = list()
		size_map[g.ip_count].append(g)

	# create a list of groups to compare and add groups_to_compare amount of generated groups to it (randomly selected on the groups_list)
	to_compare = list()
	for _ in range(int(start_cli_args.groups_to_compare)):
		to_compare.append(groups_list[random.randint(0, len(groups_list) - 1)])
	#print(f"\n\nAdded {len(to_compare)} groups to the to_compare list\n\n")
	#for cg in to_compare:
#		print(f"  Group ID : {cg.group_name}")
#		for ct in cg.ip_tuples:
			#print(f"    {ipaddress.ip_address(ct[0])} --> {ipaddress.ip_address(ct[1])}")
		#print("\n")

	#print("\n\n")
	for g in to_compare:
		comparison_start = time.time()
		print(f"Looking for groups to compare with {g.group_name} : ")
		# find the groups size to be used, regarding the current group size and the similarity_percent provided value 
		percent_diff = g.ip_count * (int(start_cli_args.similarity_percent) / 100)
		min_compare_size = math.floor(g.ip_count - percent_diff)
		max_compare_size = math.ceil(g.ip_count + percent_diff)

		# add the matching groups (regarding size only) to the target_groups_list 
		target_groups_list = list()
		any([target_groups_list.extend(y) for x, y in size_map.items() if x >= min_compare_size and x <= max_compare_size])
		target_groups_list.remove(g)
		print(f"{g.group_name} --> group size is {g.ip_count} looking for groups sized between {min_compare_size} and {max_compare_size} ({len(target_groups_list)} groups matched)")

		best_match_group = None
		best_match = 0 
		best_left_group = None
		best_left_match = 0, 0
		best_right_group = None
		best_right_match = 0, 0

		for tg in target_groups_list:
			#print(f"  Comparing with {tg.group_name} ")
			#for cg in tg.ip_tuples:
			#	print(f"    {ipaddress.ip_address(cg[0])} --> {ipaddress.ip_address(cg[1])}")
			intersection, diff, left_diff, right_diff, percent_match = compare_groups(g, tg)
			#print(f"{g.group_name} <--> {tg.group_name} : Intersection is {intersection}, diff is {diff}, L/R diff is {left_diff} / {right_diff}, match is {percent_match} %")
			if percent_match > best_match:
				best_match_group = tg
				best_match = percent_match
			#if best_left_match[0] == 0 or (percent_match > best_left_match[1] and left_diff < best_left_match[0]):
				#best_left_match = left_diff, percent_match
				#best_left_group = tg
			#if best_right_match[0] == 0 or (percent_match > best_right_match[1] and right_diff < best_right_match[0]):
			#	best_right_match = right_diff, percent_match
			#	best_right_group = tg
			#print("\n\n")

		if start_cli_args.show_groups:
			for tup in g.ip_tuples:
				print(f"  {ipaddress.ip_address(tup[0])} --> {ipaddress.ip_address(tup[1])}")
		if best_match_group:
			print(f"  Best match for {g.group_name} is {best_match_group.group_name} at {best_match} %")
			if start_cli_args.show_groups:
				for tup in best_match_group.ip_tuples:
					print(f"  {ipaddress.ip_address(tup[0])} --> {ipaddress.ip_address(tup[1])}")
		else:
			print(f"NO MATCHING GROUP FOUND")
		print(f"Comparison done in {(time.time() - comparison_start) * 1000} ms")
		print("\n\n===============================================\n\n")


if __name__ == "__main__":
	main()