import ipaddress

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
			self.ip_tuples = list(merged_tuples)
			print(self.ip_tuples)
			#print("\n\n")
		self.ip_count = calc_group_size(self)

def calc_group_size(group):
	size = 0
	for g in group.ip_tuples:
		size += g[1] - g[0] + 1
	return size

def compare_groups(g1, g2):
	i, j = 0, 0 
	intersect_nb = 0
	left_diff = 0
	right_diff = 0
	count_diff = 0

	while i < len(g1.ip_tuples) and j < len(g2.ip_tuples): 
		if g1.ip_tuples[i][1] >= g2.ip_tuples[j][0]:
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


def main():
	a = AddressGroup("test1")
	a.add_range("192.168.1.0/24")
	b = AddressGroup("test2")
	b.add_range("192.168.1.128/25")

	a.merge_ip_tuples()
	b.merge_ip_tuples()

	print(compare_groups(a, b))

if __name__ == "__main__":
	main()