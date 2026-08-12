# 05 — Issuances and credits

This chapter covers the Issuances page and the individual credit records behind it. Where the
Projects page is organised around *what was done*, this page is organised around *what was minted* —
the tokens themselves, their supply, when they were created and which project they belong to.

## The issuances table

Each row is a credit token issued on the selected Hedera network.

| Column | What it means |
|---|---|
| **Token** | The token's name. |
| **Symbol** | Its short ticker. |
| **Type** | Fungible or non-fungible. Fungible credits are interchangeable units; non-fungible ones (NFTs) have individually identifiable serial numbers. |
| **Mint Amount** | How many credits were minted. For NFTs this is a count of serials rather than a tonnage. |
| **Mint Date** | When the minting happened. |
| **Project** | The project the issuance is attributed to, linked through to its record. |
| **Methodology** | The policy the project was verified under. |
| **Registry** | The registry behind that methodology. |
| **Raw Data** | Opens the original on-chain record. |

Click a row to open the credit record.

## Filtering

The filter bar behaves exactly as it does on Projects — search text plus any combination of filters,
with a live result count and a summary strip showing total supply, and how many registries and
projects the results span.

| Filter | Notes |
|---|---|
| **Token Type** | Fungible or non-fungible. |
| **Registry** | One or more registries. |
| **Mint Amount** | A numeric range rather than an exact value. |
| **Mint Date** | A date range. |
| **Hide issuances with no project link** | A checkbox, on by default. See below. |

### Unlinked issuances

Some tokens on the ledger cannot (yet) be matched to a project in the catalogue. That usually means
the project's own records have not been indexed yet, or the token was minted outside the normal
policy flow.

By default those rows are hidden, because for most questions they are noise. Uncheck **Hide issuances
with no project link** to see them — useful when you are auditing coverage, or hunting for a token
you know exists but cannot find in the filtered view.

## Quick filters and Download Data

The **Quick filters:** row offers presets such as *Fungible tokens*, *Non-Fungible (NFTs)*, *Minted
2024* and *Minted 2025*.

The **Download Data** CSV export works identically to the Projects page and is open to everyone —
the CSV contains exactly the current filtered, sorted view. **Saving** your own quick filters
requires a signed-in account.
See chapter 04 for the details and chapter 10 for the richer Reports exports.

## Scoping banners

Arriving here from elsewhere in the Atlas narrows the list and shows a banner saying so:

- *Showing issuances for …* — reached from a project record;
- *Showing issuances for …* — reached from a methodology;
- *Showing issuances for registry …* — reached from a registry.

Each has a **Clear filter** link that returns you to the full list. If a count looks unexpectedly
small, check for one of these banners before anything else.

## The issuance record

Clicking a row opens that **issuance** — a single minting event — rather than the token as a whole.
This matters because one token is often minted several times, for different projects and vintages;
a token-level page cannot tell those apart.

The header carries the token name, symbol, type and whether the issuance reconciles, followed by three
headline figures: the amount **declared**, the amount **minted on-chain**, and the reconciliation
status. Content is then split across four tabs, and the active tab appears in the address bar so you
can link straight to it.

### Summary

Where the issuance came from and what it produced: the project, methodology and registry it belongs
to, and its **serial ranges**.

Serials are listed as ranges — `1–42,278` rather than forty-two thousand rows — with the number of
credits, whether they are active or retired, and **which account holds them**. A range is split
whenever the state or the holder changes, so every serial inside one is identical in both respects.
The holder column is blank for retired credits, which no longer have one, and while ownership is still
being synced.

### Transactions

Retirements and transfers of this issuance's credits, newest first, with the date, the accounts
involved, how many credits moved and which serials.

An issuance can show retired credits here and still list no retirement transaction. That is not a
gap in the page: retirement is counted from the ledger marking serials destroyed, but a retirement
*transaction* only exists where the registry used Guardian's retirement contract. Credits wiped
outside it are genuinely retired, yet nothing on-chain records who did it or when. The page says so
where it happens.

### Token Information

The token behind the issuance: current supply, credits minted across every project using that token
and for this issuance's project alone, the token's other issuances, and the projects sharing it.

A token serving several projects is normal. The issuance itself always belongs to exactly one — shown
under Summary.

### Advanced

The on-chain identifiers: token id, policy topic, creation date, issuer DID, and the consensus
timestamps of both the mint credential and its verifiable presentation. Each can be copied, and those
that resolve on Hedera link straight to HashScan.

---

## The token record

Older links to a token rather than an issuance open the token's newest issuance. Tokens with no
Guardian mint credential behind them keep the token-level view described below.

### Details

The main tab.

- **Token Supply** — how many units currently exist. Where the Atlas can reach the Hedera Mirror
  Node, this figure is fetched live and carries a **Live** badge, meaning it reflects the ledger right
  now rather than the last sync.
- **Total Minted (All)** — every unit ever minted for this token id, across all projects.
- **Total Minted (Project)** — the portion minted for the project you arrived from.
- **Last Mint Date** and the token's creation date.
- **Related Token Issuances** — other issuance events sharing the same token id.

**When total minted and current supply disagree.** This is normal and expected, not an error. Minting
only ever adds; supply falls when credits are **retired** (permanently destroyed for offsetting).
A gap between the two therefore tells you that some of the credits have been used. Note that
**transfers** do not change supply at all — moving credits between holders leaves the total
untouched.

**Declared vs actually minted.** These are different things and the Atlas shows both. The *declared*
amount is what the registry's Guardian mint document said it was issuing. The *minted on-chain*
amount is what the Hedera ledger actually recorded. A warning appears when they disagree:

- **Fewer minted than declared** — the mint partially failed, or never completed. Retirement is *not*
  the cause: retired credits still count as minted.
- **More minted than declared** — extra credits were minted on the ledger beyond what the document
  claimed. Nothing forces the two to match; they are separate actions by the registry.
- **Not matched yet** — the on-chain mint has not been linked to the document yet, so the declared
  figure is shown as a fallback. This resolves itself as syncing catches up.

**What the Atlas does not count.** Only credits issued through a Guardian mint document the Atlas has
synced are tracked. Serials minted outside that flow have no project, methodology or vintage behind
them, so they are deliberately excluded rather than guessed at.

### Transactions

The Guardian records of transactions attributed to this token, with the date, amount and token type
for each. Where you arrived from a specific project, the tab is scoped to that project's share; where
you came in from the issuances list, it shows the token's activity across all projects. The subtitle
above the table tells you which of the two you are looking at.

### Linkage

The provenance chain: which **project** the token belongs to, which **methodology** that project runs
under, and which **registry** published that methodology. Each is a link, and each states how the
connection was derived — the methodology comes via the token-to-project relationship, the registry via
token to project to methodology. Where a link genuinely does not exist, the tab says so plainly
("No project linked") rather than leaving a blank.

### Advanced

The on-chain identifiers: the token policy id, the token id, the token creation date and the issuing
DID, plus a link to view the token on HashScan for independent verification.

---

Next: [06 — Methodologies](06-methodologies.md) · Back to [index](README.md)
