import json


try:
    with open('enterprise-attack.json', 'r') as file:
        data = json.load(file)
    # print("JSON data loaded successfully:", data)
except FileNotFoundError:
    print("Error: The file 'your_file.json' was not found.")
except json.JSONDecodeError:
    print("Error: Failed to decode JSON from the file. Check for malformed JSON.")

# print(len(data["objects"]))

mydict = dict()
otherdict = dict()

for i in data["objects"]:
    if i["type"] == "relationship" and ("campaign" in i["source_ref"]  or "intrusion-set" in i["source_ref"]) and "attack-pattern" in i["target_ref"]:
        if i["target_ref"] not in mydict:
            mydict[i["target_ref"]] = 0
        mydict[i["target_ref"]] += 1

    elif i["type"] == "attack-pattern":
        otherdict[i["id"]] = i["name"]

sorted_items = sorted(mydict.items(), key=lambda x: x[1])
# print(sorted_items)
for i in sorted_items:
    print(f"{otherdict[i[0]]} has {i[1]} occurrences")




        