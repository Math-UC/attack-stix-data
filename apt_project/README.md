## Virtual Environment
The virtual environment is set up to sync everyone's packages locally. This allows everyone 

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