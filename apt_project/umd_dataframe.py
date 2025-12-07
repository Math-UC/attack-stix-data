#!/usr/bin/env python
# coding: utf-8

# In[14]:


import sys
from pathlib import Path

ROOT = Path().resolve().parents[1] # go up n levels (adjust as needed)
sys.path.append(str(ROOT))

from config import PROJECT_ROOT, APT_ROOT
from apt_project import *


# In[15]:


import pandas as pd
from rapidfuzz import fuzz, process
import re


# ## Create Dataframes

# In[16]:

umd_df = pd.read_csv(APT_ROOT / "dfs/umd_cyber_events_database.csv")

# Drop unnecessary columns
drop_cols = ["nato", "eu", "shanghai_coop", "oas", "mercosur", "au", "ecowas", "asean", "opec", "gulf_coop", "g7", "g20", "aukus", "csto", "oecd", "osce", "five_eyes"]

umd_df = umd_df.drop(columns=drop_cols)

#umd_df


# In[17]:


# Prep list of all known APT groups and their aliases

# Normalization helper
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


# In[18]:


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

#umd_apts_df
#umd_apts_df.sample(20)


# ## Export Dataframes

# In[19]:


# ======================================================
# Public exports (what gets imported from the package)
# ======================================================

__all__ = [
    "umd_apts_df"
]

