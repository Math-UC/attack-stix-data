#!/usr/bin/env python
# coding: utf-8



import sys
from pathlib import Path

ROOT = Path().resolve().parents[2] # go up n levels (adjust as needed)
sys.path.append(str(ROOT))

from config import PROJECT_ROOT, APT_ROOT, ENTERPRISE_ATTACK_DATA, MOBILE_ATTACK_DATA, ICS_ATTACK_DATA



import json
import pandas as pd
from rapidfuzz import fuzz, process
import re


# Load the JSON and create a master DataFrame of STIX objects



enterprise_file = ENTERPRISE_ATTACK_DATA / "enterprise-attack.json"
mobile_file = MOBILE_ATTACK_DATA / "mobile-attack.json"
ics_file = ICS_ATTACK_DATA / "ics-attack.json"

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

#master_df.head()


# Extract techniques (ATT&CK `attack-pattern` objects)



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
#tech_df.head()


# Extract tactics (from kill_chain_phases) — canonicalize into a DataFrame



# Many ATT&CK bundles don't provide tactic objects as separate 'x-mitre-tactic' entries,
# but techniques include kill_chain_phases referencing 'mitre-attack' phase_name (tactic).
# We'll get the unique list of tactics from the techniques kill_chain_phases:

tactics = sorted({phase for phases in tech_df["kill_chain_phases"].tolist() for phase in phases if phase})
tactics_df = pd.DataFrame({"tactic": tactics})
#tactics_df


# Relationships DataFrame (useful for group->technique and other links)



rel_objs = [o for o in objects if o.get("type") == "relationship"]

rel_df = pd.DataFrame([{
    "id": o.get("id"),
    "relationship_type": o.get("relationship_type"),
    "source_ref": o.get("source_ref"),
    "target_ref": o.get("target_ref"),
    "description": o.get("description"),
    "raw": o
} for o in rel_objs])

#rel_df.head()


# Map techniques to tactics (exploded rows, easy to group)



# explode kill_chain_phases into row-per-technique-per-tactic
tech_exploded = tech_df.explode("kill_chain_phases").rename(columns={"kill_chain_phases":"tactic"})
tech_exploded = tech_exploded[["id","external_id","tech_name","tactic","platforms"]]
#tech_exploded.head()


# ## Create Dataframes



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

#groups_df




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




tech_counts = (
    group_techniques_df
        .groupby("group_name")["technique_id"]
        .nunique()                      # count unique techniques per group
        .reset_index(name="technique_count")
        .sort_values("technique_count", ascending=False)
)

#tech_counts


# ## UMD Cyber Events Database



umd_df = pd.read_csv("umd_cyber_events_database.csv")

# Drop unnecessary columns
drop_cols = ["nato", "eu", "shanghai_coop", "oas", "mercosur", "au", "ecowas", "asean", "opec", "gulf_coop", "g7", "g20", "aukus", "csto", "oecd", "osce", "five_eyes"]

umd_df = umd_df.drop(columns=drop_cols)

#umd_df




# Prep list of all known APT groups and their aliases

def normalize(s):
    return str(s).strip().lower()

# 1. Canonical names
apt_names = groups_df["name"].dropna().tolist()

# 2. All alias lists flattened
alias_lists = groups_df["aliases"].dropna().tolist()
apt_aliases = [alias for sublist in alias_lists for alias in sublist]

# 3. Combined list
all_apt_terms = apt_names + apt_aliases

# 4. Normalize
all_apt_terms_norm = [normalize(x) for x in all_apt_terms]

# 5. Deduplicate + sort
all_apt_terms_norm = sorted(set(all_apt_terms_norm))

# 6. Build alias → canonical mapping
apt_map = {}
for _, row in groups_df.iterrows():
    canon = normalize(row["name"])
    apt_map[canon] = canon
    if isinstance(row["aliases"], list):
        for alias in row["aliases"]:
            apt_map[normalize(alias)] = canon




# Normalization helper
def normalize(s):
    return str(s).strip().lower()

paren_regex = re.compile(r"\((.*?)\)")

# Splits the actor field into tokens
def split_actor_tokens(text):
    if not isinstance(text, str) or not text.strip():
        return [], []

    text_norm = normalize(text)

    # Extract text inside parentheses
    inside = paren_regex.findall(text_norm)

    # Remove parentheses content to get the "outside" content
    outside_part = paren_regex.sub(" ", text_norm)

    # Tokenize outside words
    outside_tokens = outside_part.split()

    return inside, outside_tokens

ignore_tokens = {"group", "team", "play", "unit", "actor"}

# Match tokens to the apt list
def fuzzy_match_tokens(tokens, threshold):
    matches = []

    for token in tokens:
        a = normalize(token)

        # Ignore trivial / junk tokens
        if len(token) < 3:
            continue
        if token in ignore_tokens:
            continue

        result = process.extractOne(
            token,
            all_apt_terms_norm,
            scorer=fuzz.token_sort_ratio
        )

        if not result:
            continue

        match_term, score, idx = result

        if score >= threshold:
            # Map matched alias → canonical group name
            canonical = apt_map.get(match_term)
            if canonical:
                matches.append(canonical)

    return matches if matches else None

# Match the tokens inside and outside the parentheses separately
def match_actor(actor):
    inside_tokens, outside_tokens = split_actor_tokens(actor)

    # Try parentheses first (usually highest quality)
    inside_match = fuzzy_match_tokens(inside_tokens, threshold=80)
    if inside_match:
        return inside_match[0]  # return the first canonical match

    # Then try tokens outside parentheses
    outside_match = fuzzy_match_tokens(outside_tokens, threshold=85)
    if outside_match:
        return outside_match[0]

    return None

umd_df["apt_group"] = umd_df["actor"].apply(match_actor)

umd_apts_df = umd_df[umd_df["apt_group"].notna()].reset_index(drop=True)

#umd_apts_df.sample(20)


# ## Export Dataframes



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

def umd_apts_df():
    return umd_apts_df

