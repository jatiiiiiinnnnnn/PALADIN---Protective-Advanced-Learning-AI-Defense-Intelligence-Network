import pandas as pd
import glob
import os

print("Finding all dataset files...")
project_path = "C:/Users/reach/Documents/PALADIN---Protective-Advanced-Learning-AI-Defense-Intelligence-Network/training_data"
files = glob.glob(f"{project_path}/*.parquet")

if not files:
    print("Error: No parquet files found in the training_data folder!")
    exit()

# 1. Load everything
df_list = []
for file in files:
    print(f"Loading {os.path.basename(file)}...")
    df_list.append(pd.read_parquet(file))

# 2. Combine into one giant table
print("Merging files...")
df_all = pd.concat(df_list, ignore_index=True)
df_all.columns = df_all.columns.str.strip() # Clean column names
print(f"Total raw rows: {len(df_all):,}")

# 3. Smart Sampling (The Bulletproof Method)
MAX_ROWS_PER_CLASS = 20000 
print(f"Balancing classes (Max {MAX_ROWS_PER_CLASS} per class)...")

# Using a loop instead of .apply() prevents Pandas from deleting the Label column
balanced_chunks = []
for label, group in df_all.groupby('Label'):
    sampled_group = group.sample(n=min(len(group), MAX_ROWS_PER_CLASS), random_state=42)
    balanced_chunks.append(sampled_group)

# Combine the chunks back together
df_balanced = pd.concat(balanced_chunks, ignore_index=True)

print(f"Balanced dataset size: {len(df_balanced):,}")
print("\nNew Class Distribution:")
print(df_balanced['Label'].value_counts())

# 4. Save the master file back to the training folder
output_path = f"{project_path}/CIC_IDS_MASTER_BALANCED.parquet"
df_balanced.to_parquet(output_path)
print(f"\nMaster balanced dataset saved to:\n{output_path}")