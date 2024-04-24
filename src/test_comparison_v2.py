import ipaddress

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
						print(min_add)
						print(max_add)
						merged_tuples.add((min_add, max_add))
						print(f"Merged {ipaddress.ip_address(tuples_list[tup_index-1][0])} / {ipaddress.ip_address(tuples_list[tup_index-1][1])} with {ipaddress.ip_address(tuples_list[tup_index][0])} / {ipaddress.ip_address(tuples_list[tup_index][1])} --> ({ipaddress.ip_address(min_add)},{ipaddress.ip_address(max_add)})")
						merge_done = True
						last_loop_merged = True

					# else just add the tuple at current index - 1 to the merged_tuples set and move to the next for loop iteration 
					else:
						merged_tuples.add(tuples_list[tup_index - 1])
						print(f"Adding {tuples_list[tup_index-1]}")

						# if we are at the last index of the group, add the lat member to the merged_tuples set 
						if tup_index + 1 == len(tuples_list):
							print(f"Last index : adding {tuples_list[tup_index]}")
							merged_tuples.add(tuples_list[tup_index])

				# merge_finished is set to True if no merge has been processed on the last for loop (iteration over the full tuples set)
				merge_finished = True if not merge_done else False
				print(f"merge_finished : {merge_finished} / merge_done : {merge_done}")
				tuples_list = list(sorted(merged_tuples)) if merge_done else tuples_list
				print(tuples_list)
			self.ip_tuples = list(sorted(tuples_list))

		# once all ip_tuples have been merged, calculate the group size (number of IPs on the AddressGroup)
		self.ip_count = self.calc_group_size()

		print("\n\n")
		print(f"After merging, {self.group_name} is : ")
		for tup_c in self.ip_tuples:
			print(f"  {ipaddress.ip_address(tup_c[0])} --> {ipaddress.ip_address(tup_c[1])}")

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
	print(f"G1 min is {g1.min_ip}")
	print(f"G2 min is {g2.min_ip}")

	while last_comparison_step <= max(g1.max_ip, g2.max_ip):
		print(f"Last comparison step is {ipaddress.ip_address(last_comparison_step)}, i = {i}, j = {j}")
		print(f"Left tuple is {g1.ip_tuples[i]}")
		print(f"Right tuple is {g2.ip_tuples[j]}")
		left_active = i < len(g1.ip_tuples) and last_comparison_step >= g1.ip_tuples[i][0] and last_comparison_step <= g1.ip_tuples[i][1]
		right_active = j < len(g2.ip_tuples) and last_comparison_step >= g2.ip_tuples[j][0] and last_comparison_step <= g2.ip_tuples[j][1]
		print(f"Left active : {left_active} / Right active : {right_active}")

		if left_active and right_active:
			# we are on an intersection range
			intersect_stop = min(g1.ip_tuples[i][1], g2.ip_tuples[j][1])
			intersect_nb += intersect_stop - last_comparison_step + 1
			last_comparison_step = intersect_stop + 1
			print(f"End of intersection is {ipaddress.ip_address(last_comparison_step - 1)}, jumping to {ipaddress.ip_address(last_comparison_step)}")
			if last_comparison_step > g1.ip_tuples[i][1]:
				i += 1
				print("Incremented i")
			if last_comparison_step > g2.ip_tuples[j][1]:
				j += 1
				print("Incremented j")
		elif left_active:
			# adding to left diff
			if j < len(g2.ip_tuples):
				left_diff_stop = min(g1.ip_tuples[i][1], g2.ip_tuples[j][0] - 1)
			else:
				left_diff_stop = g1.ip_tuples[i][1]
			left_diff += left_diff_stop - last_comparison_step + 1
			last_comparison_step = left_diff_stop + 1
			print(f"End of left is {ipaddress.ip_address(last_comparison_step - 1)}, jumping to {ipaddress.ip_address(last_comparison_step)}")
			if last_comparison_step > g1.ip_tuples[i][1]:
				i += 1
				print("Incremented i")
		elif right_active:
			# adding to right diff
			if i < len(g1.ip_tuples):
				right_diff_stop = min(g2.ip_tuples[j][1], g1.ip_tuples[i][0] - 1)
			else:
				right_diff_stop = g2.ip_tuples[j][1]
			right_diff += right_diff_stop - last_comparison_step + 1
			last_comparison_step = right_diff_stop + 1
			print(f"End of right is {ipaddress.ip_address(last_comparison_step - 1)}, jumping to {ipaddress.ip_address(last_comparison_step)}")
			if last_comparison_step > g2.ip_tuples[j][1]:
				j += 1
				print("Incremented j")
		else:
			if i < len(g1.ip_tuples) and j < len(g2.ip_tuples):
				last_comparison_step = min(g1.ip_tuples[i][0], g2.ip_tuples[j][0])
				print(f"No group active, jumping to next min for i and j : {last_comparison_step}")
			elif i < len(g1.ip_tuples):
				last_comparison_step = g1.ip_tuples[i][0]
				print(f"j is over, jumping to next start value for i : {last_comparison_step}")
			else: 
				last_comparison_step = g2.ip_tuples[j][0]
				print(f"i is over, jumping to next start value for j : {last_comparison_step}")

		input("Press enter to continue")
		print("\n\n")

	print(f"G1 ip count : {g1.ip_count} / G2 ip count : {g2.ip_count}")

	# calculate the percent of match between G1 and G2 with the calculated values of intersect 
	percent_match = round(abs(intersect_nb) / (g1.ip_count + g2.ip_count - intersect_nb) * 100, 4) 

	return abs(intersect_nb), count_diff, abs(left_diff), abs(right_diff), percent_match

g1 = AddressGroup("g1")
g2 = AddressGroup("g2")

#g1.add_range("192.168.0.0/23")
#g1.add_range("205.151.80.144/28")
#g1.add_range("42.172.176.0/25")
#g2.add_range("106.109.194.0/25")
#g2.add_range("145.181.30.0/25")
#g2.add_range("137.169.128.0/19")
#g2.add_range("143.189.26.0/23")
#g2.add_range("45.24.0.0/15")
#g2.add_range("128.0.0.0/2")
#g2.add_range("85.140.163.0/25")
#g2.add_range("14.181.197.128/26")
#g2.add_range("172.128.0.0/9")
#g2.add_range("240.0.0.0/4")
#g2.add_range("194.224.0.0/11")
#g2.add_range("129.100.64.0/19")
#g2.add_range("160.0.0.0/4")
#g2.add_range("73.56.252.192/28")
#g2.add_range("39.111.7.116/30")
#g2.add_range("128.0.0.0/1")
#g2.add_range("205.151.80.144/28")
#g2.add_range("128.0.0.0/2")
#g2.add_range("97.0.0.0/12")
#g2.add_range("0.0.0.0/1")
#g2.add_range("72.112.0.0/14")
#g2.add_range("32.0.0.0/6")
#g2.add_range("80.196.92.240/30")
#g2.add_range("0.0.0.0/2")
#g2.add_range("188.159.112.0/20")
#g2.add_range("69.192.0.0/10")
#g2.add_range("42.172.176.0/25")
#g2.add_range("230.64.0.0/10")
#g2.add_range("122.253.0.0/17")
#g2.add_range("0.0.0.0/4")
g1.add_range("4.5.8.9")
g1.add_range("9.8.5.4/32")
g2.add_range("9.8.5.4")
g2.add_range("4.5.8.9/32")
g1.merge_ip_tuples()
g2.merge_ip_tuples()

intersection, diff, left_diff, right_diff, percent_match = compare_groups(g1, g2)
print(f"{g1.group_name} <--> {g2.group_name} : Intersection is {intersection}, diff is {diff}, L/R diff is {left_diff} / {right_diff}, match is {percent_match} %")