# Form Submissions Spam Analysis

A Python script that scores contact-form submissions with simple heuristics, flags likely spam, produces blocklists (IPs and e-mail domains) and visualises the results.

## What it does

1. Loads `submissions.csv` and prints a quick data overview (row count, columns, missing values).
2. Assigns every submission a **spam score** based on several signals.
3. Marks submissions with a score of **10 or more** as spam.
4. Prints summary statistics (spam count, spam %, top spam IPs).
5. Builds blocklists of IP addresses and e-mail domains that are almost exclusively spam.
6. Exports the suspicious submissions to a CSV file.
7. Draws a dashboard of charts (`spam_wykresy.png`).

## Requirements

- Python 3.8+
- `pandas`
- `matplotlib`

```
pip install pandas matplotlib
```

## Input

A file `submissions.csv` in the same folder as the script, with at least these columns:

| Column | Description |
|---|---|
| `honeypot_field` | Hidden form field; humans leave it empty, bots often fill it in |
| `form_fill_time_sec` | Time in seconds between opening and submitting the form |
| `ip` | Sender IP address |
| `email` | Sender e-mail address |
| `message_length` | Length of the message (number of characters) |

## Usage

```
python spam_analysis_wykresy.py
```

(use `python3` on Linux/macOS). A chart window opens at the end; close it to finish the script.

## Scoring rules

| Signal | Points |
|---|---|
| Honeypot field filled | +10 |
| Form filled in ≤ 3 s | +5 |
| Form filled in > 3 s and ≤ 5 s | +1 |
| IP address appears in ≥ 5 submissions | +2 |
| E-mail address (case-insensitive) appears in ≥ 5 submissions | +1 |
| Empty message (`message_length == 0`) | +1 |

A submission is classified as **spam** when its score is **≥ 10**.

## Blocklists

- **IPs**: addresses with at least 5 submissions of which at least 80% are spam.
- **E-mail domains**: domains with at least 5 submissions of which at least 80% are spam.

## Output files

| File | Content |
|---|---|
| `suspicious_submissions.csv` | All submissions classified as spam, with their scores |
| `block_ips.txt` | IPs recommended for blocking, one per line |
| `block_email_domains.txt` | E-mail domains recommended for blocking, one per line |
| `spam_wykresy.png` | Dashboard with six charts (see below) |

## Charts

1. Spam share (legitimate vs. spam)
2. `spam_score` distribution
3. Form fill time: legitimate vs. spam
4. Top 10 IP addresses (spam)
5. Top 10 e-mail domains (spam)
6. IP: all submissions vs. spam submissions (points on the dashed line are spam-only IPs; points below it are IPs with mixed traffic)

## Limitations

- **The threshold effectively depends on the honeypot.** Without a filled honeypot the maximum score is 9 (5 + 2 + 1 + 1), so no submission can reach 10 without it. Bots that skip the honeypot are not classified as spam, even if they trigger every other signal. Lowering the threshold (e.g. to 6–7) would catch them, at the cost of more false positives.
- **Shared IP addresses.** IPs with mixed traffic (e.g. offices, mobile operators) may belong to real users, so blocking them can affect legitimate visitors.
- **Fixed thresholds.** All thresholds and weights are chosen by hand and should be tuned to the actual data.

## Findings

_To be completed after running the script on the dataset: share of spam, which signals separate bots from humans, how concentrated spam is across IPs and domains, and recommended actions._