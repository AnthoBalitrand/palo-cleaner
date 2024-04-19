

def merge_ip_tuples(tuples_list):
	# this function merges contiguous IP ranges on the AddressGroup
	merge_finished = False
	tuples_list = sorted(tuples_list)
	merged_tuples = set()

	if len(tuples_list) > 1:
		while not merge_finished:
			merged_tuples = set()
			merge_done = False
			last_loop_merged = False
			#print(f"  {tuples_list}")
			#print(f"Iterating from 1 to {len(tuples_list)}")
			for tup_index in range(1, len(tuples_list)):
				#print(f"Iteration #{tup_index}")
				if last_loop_merged:
					if tup_index + 1 == len(tuples_list):
						#print(f"Adding last index value")
						merged_tuples.add(tuples_list[tup_index])
						#print(merged_tuples)
					last_loop_merged = False
					#print(f"Last iteration was a merge, jumping to next one")
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
			tuples_list = list(sorted(merged_tuples))

	return list(sorted(merged_tuples))


tuples_list = [
	(10, 20), 
	(60, 62),
	(12, 41),
	(80, 100),
	(9, 61), 
	(69, 91)
]


print(merge_ip_tuples(tuples_list))