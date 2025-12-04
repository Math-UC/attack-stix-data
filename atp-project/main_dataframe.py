#!/usr/bin/env python
# coding: utf-8

# In[3]:


import json
import pandas as pd
from pprint import pprint
import matplotlib.pyplot as plt
import networkx as nx
import seaborn as sns


# Load the JSON and create a master DataFrame of STIX objects

# In[ ]:


enterprise_file = "../enterprise-attack/enterprise-attack.json"
mobile_file = "../mobile-attack/mobile-attack.json"
ics_file = "../ics-attack/ics-attack.json"

with open(enterprise_file, "r", encoding="utf-8") as f:
    stix = json.load(f)

objects = stix.get("objects", [])
# Master dataframe (keeps the raw dict for reference)
master_df = pd.DataFrame([{
    "id": o.get("id"),  
    "type": o.get("type"),
    "name": o.get("name"),
    "description": o.get("description"),
    "created": o.get("created"),
    "modified": o.get("modified"),
    "raw": o
} for o in objects])

master_df.head()


# Extract techniques (ATT&CK `attack-pattern` objects)

# In[5]:


tech_objs = [o for o in objects if o.get("type") == "attack-pattern"]

def technique_row(o):
    # external id e.g. T1003 usually in external_references where source_name == 'mitre-attack'
    ext_refs = o.get("external_references", [])
    mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), {})
    external_id = mitre_ref.get("external_id")
    # kill_chain_phases may contain tactic phase names
    kcp = o.get("kill_chain_phases") or o.get("kill_chain_phases", []) or []
    phases = [p.get("phase_name") for p in kcp if isinstance(p, dict) and p.get("phase_name")]
    platforms = o.get("x_mitre_platforms") or o.get("x-mitre-platforms") or []
    data_sources = o.get("x_mitre_data_sources") or []
    return {
        "id": o.get("id"),
        "tech_name": o.get("name"),
        "external_id": external_id,
        "description": o.get("description"),
        "platforms": platforms,
        "kill_chain_phases": phases,
        "raw": o
    }

tech_df = pd.DataFrame([technique_row(o) for o in tech_objs])
tech_df.head()


# Extract tactics (from kill_chain_phases) — canonicalize into a DataFrame

# In[6]:


# Many ATT&CK bundles don't provide tactic objects as separate 'x-mitre-tactic' entries,
# but techniques include kill_chain_phases referencing 'mitre-attack' phase_name (tactic).
# We'll get the unique list of tactics from the techniques kill_chain_phases:

tactics = sorted({phase for phases in tech_df["kill_chain_phases"].tolist() for phase in phases if phase})
tactics_df = pd.DataFrame({"tactic": tactics})
tactics_df


# Relationships DataFrame (useful for group->technique and other links)

# In[7]:


rel_objs = [o for o in objects if o.get("type") == "relationship"]

rel_df = pd.DataFrame([{
    "id": o.get("id"),
    "relationship_type": o.get("relationship_type"),
    "source_ref": o.get("source_ref"),
    "target_ref": o.get("target_ref"),
    "description": o.get("description"),
    "raw": o
} for o in rel_objs])

rel_df.head()


# Map techniques to tactics (exploded rows, easy to group)

# In[8]:


# explode kill_chain_phases into row-per-technique-per-tactic
tech_exploded = tech_df.explode("kill_chain_phases").rename(columns={"kill_chain_phases":"tactic"})
tech_exploded = tech_exploded[["id","external_id","tech_name","tactic","platforms"]]
tech_exploded.head()


# ## Create Dataframes

# In[18]:


# Filter intrusion-set objects (groups)
group_objs = [o for o in objects if o.get("type") == "intrusion-set"]

def group_row(o):
    return {
        "id": o.get("id"),
        "name": o.get("name"),
        "aliases": o.get("aliases", []),
        "description": o.get("description"),
        "created": o.get("created"),
        "modified": o.get("modified"),
        "raw": o
    }

groups_df = pd.DataFrame([group_row(g) for g in group_objs])

groups_df.head()


# In[ ]:


# Filter relevant "uses" relationships
uses_rels = [
    r for r in rel_objs
    if r.get("relationship_type") == "uses"
    and r.get("source_ref", "").startswith("intrusion-set--")
    and r.get("target_ref", "").startswith("attack-pattern--")
]

rows = []
for r in uses_rels:
    group_id = r["source_ref"]
    tech_id = r["target_ref"]

    # Lookup group name
    group_name = next((g["name"] for g in group_objs if g["id"] == group_id), None)

    # Lookup technique information
    tech = next((t for t in tech_df.to_dict("records") if t["id"] == tech_id), None)

    rows.append({
        "group_id": group_id,
        "group_name": group_name,
        "technique_id": tech_id,
        "technique_name": tech.get("name") if tech else None,
        "tactic": tech.get("kill_chain_phases") if tech else None,
        "technique_description": tech.get("description") if tech else None,
        "relationship_description": r.get("description"),
    })

group_techniques_df = pd.DataFrame(rows)


# In[22]:


tech_counts = (
    group_techniques_df
        .groupby("group_name")["technique_id"]
        .nunique()                      # count unique techniques per group
        .reset_index(name="technique_count")
        .sort_values("technique_count", ascending=False)
)

tech_counts


# ## Export Dataframes

# In[ ]:


def main_df():
    return master_df

def tech_df():
    return tech_df

def tactics_df():
    return tactics_df

def rel_df():
    return rel_df

def groups_df():
    return groups_df

def group_techniques_df():
    return group_techniques_df

