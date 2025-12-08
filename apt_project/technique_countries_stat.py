#!/usr/bin/env python
# coding: utf-8

# In[3]:


import sys
from pathlib import Path

ROOT = Path().resolve().parents[1] # go up n levels (adjust as needed)
sys.path.append(str(ROOT))

from config import PROJECT_ROOT, APT_ROOT
from apt_project import *


# In[4]:


import pandas as pd
import numpy as np


# ## Statistical Analysis

# ### Event Dataframe
# 
# #### Core Columns Used for Statistical Analysis
# - event_id (optional index)
# - event_date
# - year
# - month
# 
# - actor                  (raw actor name)
# - apt_group              (NaN for most non-APT events)
# 
# - actor_country          (attacker origin)
# - country                (victim country)
# 
# #### Contextual Features for ML
# - industry
# - industry_code
# - organization
# - actor_type
# - motive
# 
# - event_type
# - event_subtype
# - magnitude
# - duration
# - scope
# 
# #### Statistical Targets to be Computed
# - origin_risk_norm       <-- statistical label for ML target 1
# - victim_risk_norm       <-- statistical label for ML target 2

# In[5]:


# Load and clean the dataset

events_df = umd_df.copy()

# Ensure consistent capitalization / missing values
events_df['actor_country'] = events_df['actor_country'].fillna('Undetermined').str.strip()
events_df['country'] = events_df['country'].fillna('Undetermined').str.strip()
events_df['apt_group'] = events_df['apt_group'].fillna(np.nan)

origin_df = events_df[
    events_df['actor_country'].notna() &
    (events_df['actor_country'].str.lower() != 'undetermined') &
    (events_df['actor_country'].str.strip() != '')
]

victim_df = events_df[
    events_df['country'].notna() &
    (events_df['country'].str.lower() != 'undetermined') &
    (events_df['country'].str.strip() != '')
]


# In[6]:


# Compute the origin risk (attacker-country risk)

# Count attacks originating from each country
origin_counts = origin_df.groupby('actor_country').size().reset_index(name='attack_count')

# Probability-style risk score
total_origin_events = len(origin_df)
origin_counts['origin_risk'] = origin_counts['attack_count'] / total_origin_events

origin_max = origin_counts['attack_count'].max()

# Uses Laplace smoothing and a logarithmic distribution
origin_counts['origin_risk_norm'] = (
    np.log(origin_counts['attack_count'] + 1) /
    np.log(origin_max + 1)
)

# Make lookup dict for fast mapping into main df
origin_risk_map = origin_counts.set_index('actor_country')['origin_risk_norm'].to_dict()

# Add origin risk to every event
events_df['origin_risk_norm'] = events_df['actor_country'].map(origin_risk_map)


# In[7]:


origin_counts.sort_values('attack_count', ascending=False).head(10)


# In[8]:


# Compute the victim risk (victim-country risk)

# Count attacks targeting each country
victim_counts = victim_df.groupby('country').size().reset_index(name='victim_count')

# Probability-style risk score
total_victim_events = len(victim_df)
victim_counts['victim_risk'] = victim_counts['victim_count'] / total_victim_events

victim_max = victim_counts['victim_count'].max()

# Uses Laplace smoothing and a logarithmic distribution
victim_counts['victim_risk_norm'] = (
    np.log(victim_counts['victim_count'] + 1) /
    np.log(victim_max + 1)
)

# Make lookup dict for fast mapping into main df
victim_risk_map = victim_counts.set_index('country')['victim_risk_norm'].to_dict()

# Add victim risk to every event
events_df['victim_risk_norm'] = events_df['country'].map(victim_risk_map)


# In[9]:


#victim_counts.sort_values('victim_count', ascending=False).head(10)


# In[10]:


# Compute APT origin score

# Filter to rows with APT attribution
apt_events_df = events_df[events_df['apt_group'].notna()].copy()

# Determine each APT’s most common origin country
apt_origin_country = (
    apt_events_df.groupby('apt_group')['actor_country']
    .agg(lambda x: x.value_counts().idxmax())  # most frequent country
    .reset_index(name='apt_origin_country')
)

# Lookup origin-risk for those countries
apt_origin_country['apt_origin_risk_score'] = (
    apt_origin_country['apt_origin_country'].map(origin_risk_map)
)


# In[11]:


#apt_origin_country


# In[12]:


# Compute APT victim score

# Mean victim_risk_norm for each apt_group
apt_victim_score = (
    apt_events_df.groupby('apt_group')['victim_risk_norm']
    .mean()
    .reset_index(name='apt_victim_risk_score')
)


# In[13]:


#apt_victim_score


# In[14]:


# Combine into final APT-level score table

apt_scores_df = (
    apt_origin_country
    .merge(apt_victim_score, on='apt_group', how='outer')
    .rename(columns={
        "apt_origin_country": "origin_country",
        "apt_origin_risk_score": "origin_risk",
        "apt_victim_risk_score": "target_risk",
    })
)

# Add APT event counts
apt_scores_df['num_events'] = (
    apt_events_df.groupby('apt_group').size().reindex(apt_scores_df['apt_group']).values
)

# Set missing scores to the median
median_origin = apt_origin_country["apt_origin_risk_score"].median()
median_victim = apt_victim_score["apt_victim_risk_score"].median()

apt_origin_country["apt_origin_risk_score"] = apt_origin_country["apt_origin_risk_score"].fillna(median_origin)
apt_victim_score["apt_victim_risk_score"] = apt_victim_score["apt_victim_risk_score"].fillna(median_victim)


# Sort for readability
apt_scores_df = apt_scores_df.sort_values('target_risk', ascending=False).reset_index(drop=True)


# In[15]:


#apt_scores_df

