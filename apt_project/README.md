## Virtual Environment
The virtual environment is set up to sync everyone's packages locally. This allows everyone to use each other's notebooks.

> [!warning]
> This may remove/delete any virtual environments already set up in the current directory (`/attack-stix-data/atp-project`)

### Setting Up/Running
1. Run the startup script to check for and setup up the virtual environment locally (this also checks and updates `requirements.txt`)

```sh
bash setup.sh
```

2. Activate the environment to begin using it

```sh
source venv/bin/activate
```

### Updating Packages
1. After installing or updating packages via `pip`, add them to `requirements.txt` and push the changes

```sh
pip freeze > requirements.txt
```

## Analysis Notebooks
Add this code block at the top of every notebook to have access to all of the importable dataframes:

```python
import sys
from pathlib import Path

ROOT = Path().resolve().parents[1] # go up n levels (adjust as needed)
sys.path.append(str(ROOT))

from config import PROJECT_ROOT, APT_ROOT
from apt_project import *
```

> [!note]
> Increment the depth (n) until the config file can be found