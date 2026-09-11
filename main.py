import pandas as pd

df = pd.read_csv("submissions.csv")

print("Total listed:", len(df))
print("Kolumns:", df.columns.tolist())
print("Empty fields:\n", df.isna().sum())

df["spam_score"] = 0

#if the field is filled - add max score - 10
honeypot = df["honeypot_field"].fillna("").astype(str).str.strip()
for index, value in honeypot.items():
    if value:
        df.loc[index, "spam_score"] += 10

#if time is too short - add 5 points
df.loc[df["form_fill_time_sec"] <= 3, "spam_score"] += 5
# could be suspicious
df.loc[(df["form_fill_time_sec"] > 3) & (df["form_fill_time_sec"] <= 5), "spam_score"] += 1

#the most common ip
ip_counts = df["ip"].map(df["ip"].value_counts())
df.loc[ip_counts >= 5, "spam_score"] += 2

# email is too frequent
email = df["email"].str.lower()
email_counts = email.value_counts()
df.loc[email.map(email_counts) >= 5, "spam_score"] += 1

df.loc[df["message_length"] == 0, "spam_score"] += 1

df["is_spam"] = df["spam_score"] >= 10
spam = df[df["is_spam"]].copy()

print("\nResults")
print("Total check:", len(df))
print("Spam:", len(spam))
print("Spam %:", round(len(spam) / len(df) * 100, 2))


print("\nTop spam IP:")
print(spam["ip"].value_counts().head(10))

ip_stats = df.groupby("ip").agg(
    total=("is_spam", "size"),
    spam=("is_spam", "sum")
)

block_ips = ip_stats[
    (ip_stats["total"] >= 5) &
    (ip_stats["spam"] / ip_stats["total"] >= 0.8)
].index

# creating the file for blocking ip
with open("block_ips.txt", "w") as f:
    f.write("\n".join(block_ips))

domain_stats = df.assign(
    email_domain=df["email"].str.lower().str.split("@").str[-1]
).groupby("email_domain").agg(
    total=("is_spam", "size"),
    spam=("is_spam", "sum")
)

block_domains = domain_stats[
    (domain_stats["total"] >= 5) &
    (domain_stats["spam"] / domain_stats["total"] >= 0.8)
].index

#creating file for blocking domains
with open("block_email_domains.txt", "w") as f:
    f.write("\n".join(block_domains))

#spam info to the file
spam.to_csv("suspicious_submissions.csv", index=False)

print("\nCreated files:")
print("suspicious_submissions.csv")
print("block_ips.txt")
print("block_email_domains.txt")

