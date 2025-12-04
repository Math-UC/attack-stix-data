import re
import sys
from pathlib import Path

def remove_cell_tags(input_path, output_path=None):
    input_path = Path(input_path)

    if output_path is None:
        output_path = input_path  # overwrite original file
    else:
        output_path = Path(output_path)

    with open(input_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    cleaned = []
    cell_tag_patterns = [
        r"^# In\[\d*\]:.*$",  # "# In[12]:"
        r"^# In\[.*\]:.*$",   # "# In[something]:"
        r"^# %%.*$",          # "# %%"
        r"^# <cell>.*$",      # "# <cell>"
        r"^# Cell.*$",        # "# Cell x"
    ]

    # Compile into a single regex OR pattern
    combined = re.compile("|".join(cell_tag_patterns))

    for line in lines:
        if not combined.match(line.strip()):
            cleaned.append(line)

    # Write cleaned content
    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(cleaned)

    print(f"Cleaned file written to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python clean_cells.py <input_file.py> [output_file.py]")
    else:
        remove_cell_tags(*sys.argv[1:])
