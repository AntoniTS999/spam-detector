import pandas as pd

import matplotlib.pyplot as plt

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

# Charts

fig, axes = plt.subplots(2, 3, figsize=(18, 10))
fig.suptitle("Analiza zgłoszeń formularza – spam vs. poprawne", fontsize=16)

# 1. Spam share
counts = df["is_spam"].value_counts().reindex([False, True], fill_value=0)
axes[0, 0].pie(counts, labels=["Poprawne", "Spam"], autopct="%1.1f%%",
               colors=["#4caf50", "#e53935"], startangle=90)
axes[0, 0].set_title("Udział spamu")

# 2. spam_score distribution
score_counts = df["spam_score"].value_counts().sort_index()
bar_colors = ["#e53935" if s >= 10 else "#4caf50" for s in score_counts.index]
axes[0, 1].bar(score_counts.index.astype(str), score_counts.values, color=bar_colors)
axes[0, 1].set_title("Rozkład spam_score (czerwone = spam)")
axes[0, 1].set_xlabel("spam_score")
axes[0, 1].set_ylabel("Liczba zgłoszeń")

# 3.  Form fill time: legitimate vs spam
cap = 60
for label, mask, color in [("Poprawne", ~df["is_spam"], "#4caf50"),
                           ("Spam", df["is_spam"], "#e53935")]:
    axes[0, 2].hist(df.loc[mask, "form_fill_time_sec"].clip(upper=cap), bins=30,
                    alpha=0.6, label=label, color=color)
axes[0, 2].set_title(f"Czas wypełnienia formularza (obcięte do {cap} s)")
axes[0, 2].set_xlabel("Sekundy")
axes[0, 2].legend()

# 4. Top 10 IPs with spam
top_ips = spam["ip"].value_counts().head(10).sort_values()
axes[1, 0].barh(top_ips.index.astype(str), top_ips.values, color="#e53935")
axes[1, 0].set_title("Top 10 adresów IP (spam)")

# 5. Top 10 email domains with spam
spam_domains = (spam["email"].str.lower().str.split("@").str[-1]
                .value_counts().head(10).sort_values())
axes[1, 1].barh(spam_domains.index.astype(str), spam_domains.values, color="#fb8c00")
axes[1, 1].set_title("Top 10 domen e-mail (spam)")

# 6.  IP: all submissions vs spam submissions
axes[1, 2].scatter(ip_stats["total"], ip_stats["spam"], alpha=0.5, color="#8e24aa")
mx = max(ip_stats["total"].max(), 1)
axes[1, 2].plot([0, mx], [0, mx], ls="--", color="gray", label="IP wyłącznie spamowe")
axes[1, 2].set_xlabel("Wszystkie zgłoszenia z IP")
axes[1, 2].set_ylabel("Zgłoszenia spamowe z IP")
axes[1, 2].set_title("IP: czysto spamowe vs. mieszane")
axes[1, 2].legend(fontsize=8)

plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig("spam_wykresy.png", dpi=150)
plt.show()
