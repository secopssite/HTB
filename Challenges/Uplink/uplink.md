<div align="center">

# Uplink — HackTheBox

![Difficulty](https://img.shields.io/badge/Difficulty-Insane-purple?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Coding-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Solved-success?style=for-the-badge)

<img src="../../assets/MrsNobody.png" width="200" alt="MrsNobody">

**MrsNobody**

---

</div>

> **Disclaimer:** This writeup is for educational purposes only, performed in an authorized Hack The Box environment.

## Challenge Information

| Property | Value |
|----------|-------|
| Challenge | Uplink |
| Category | Coding |
| Difficulty | Insane |
| Points | 80 |
| Creator | DonutMaster123 |
| Algorithm | Li Chao Tree (Convex Hull Trick) on Tree DP |

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Example](#example)
3. [Analysis](#analysis)
4. [DP Formulation](#dp-formulation)
5. [Convex Hull Trick Optimization](#convex-hull-trick-optimization)
6. [Li Chao Tree with Undo](#li-chao-tree-with-undo)
7. [Full Solution (C++)](#full-solution-c)
8. [Flag](#flag)

---

## Problem Statement

Given a **rooted tree** of N computers (node 1 = root), each node can "jump" to any ancestor. Each jump from node `u` to ancestor `a` costs:

```
cost = distance(u, a) * transfer[u] + prep[u] + receive[a]
```

Where `distance(u, a)` is the sum of edge weights on the path. Find the **minimum total time** for each node to relay information to the root through optimal jump sequences.

**Constraints:**
- 2 <= N <= 500,000
- 1 <= parent[i] < i
- Values up to 10^6

---

## Example

```
Input:
6
0 0 0 0 4
1 3 3 7 2
1 4 5 2 6
3 7 9 3 4
3 2 4 1 5
2 10 6 0 9

Output:
20 26 98 29 82
```

**Node 4 example:** Jump to Node 3 (cost 72), then Node 3 jumps to Node 1 (cost 26) = 98 total.

---

## Analysis

### Brute Force: O(N * depth)

For each node, try all ancestors and pick the cheapest sequence. For balanced trees this is O(N log N), but for a chain it's **O(N^2) = 2.5 * 10^11** — way too slow.

### Key Insight: Convex Hull Trick

The DP recurrence has a **linear structure** that enables the Convex Hull Trick optimization.

---

## DP Formulation

Define `cum[i]` = cumulative edge distance from root to node `i`.

```
dp[i] = min over ancestors a of i:
    (cum[i] - cum[a]) * transfer[i] + prep[i] + receive[a] + dp[a]
```

Expanding:

```
dp[i] = transfer[i] * cum[i] + prep[i] + min_a(-cum[a] * transfer[i] + receive[a] + dp[a])
```

For each ancestor `a`, define a **line**:

```
L_a(x) = -cum[a] * x + (receive[a] + dp[a])
```

Query at `x = transfer[i]` to get the minimum.

This is exactly the **Convex Hull Trick** — finding the minimum of a set of linear functions at a query point.

---

## Convex Hull Trick Optimization

### Challenge: Tree Structure

On a tree, the set of active lines changes as we DFS:
- **Enter a node:** insert its line (it becomes an ancestor for its descendants)
- **Leave a node:** remove its line (it's no longer an ancestor)

This requires a data structure that supports **insert, query, and undo**.

### Solution: Li Chao Tree with Rollback

A **Li Chao Tree** is a segment tree over the query domain that supports:
- `insert(line)` in O(log V)
- `query(x)` in O(log V)
- **Undo** by maintaining a stack of modifications

**Coordinate compression** on transfer values reduces the segment tree size from 10^6 to at most N.

### Complexity

| Operation | Time |
|-----------|------|
| Insert | O(log N) |
| Query | O(log N) |
| Undo | O(log N) amortized |
| **Total** | **O(N log N)** |

---

## Full Solution (C++)

```cpp
#include <bits/stdc++.h>
using namespace std;
typedef long long ll;
const ll INF = 2e18;

struct Line {
    ll m, b;
    ll eval(ll x) const { return m * x + b; }
};

struct LiChao {
    int n;
    vector<ll> xs;
    vector<Line> tree;
    vector<bool> has;
    vector<tuple<int,Line,bool>> undo;

    void init(vector<ll>& v) {
        sort(v.begin(), v.end());
        v.erase(unique(v.begin(), v.end()), v.end());
        xs = v; n = xs.size();
        tree.resize(4*n+4);
        has.resize(4*n+4, false);
    }

    void ins(int nd, int lo, int hi, Line nl) {
        if (lo == hi) {
            if (!has[nd] || nl.eval(xs[lo]) < tree[nd].eval(xs[lo])) {
                undo.push_back({nd, tree[nd], has[nd]});
                tree[nd] = nl; has[nd] = true;
            }
            return;
        }
        if (!has[nd]) {
            undo.push_back({nd, tree[nd], has[nd]});
            tree[nd] = nl; has[nd] = true; return;
        }
        int mid = (lo+hi)/2;
        bool lb = nl.eval(xs[lo]) < tree[nd].eval(xs[lo]);
        bool mb = nl.eval(xs[mid]) < tree[nd].eval(xs[mid]);
        if (mb) { undo.push_back({nd, tree[nd], has[nd]}); swap(tree[nd], nl); }
        if (lb != mb) ins(2*nd, lo, mid, nl);
        else ins(2*nd+1, mid+1, hi, nl);
    }

    void insert(Line l) { if(n>0) ins(1, 0, n-1, l); }

    ll qry(int nd, int lo, int hi, int idx) {
        ll res = has[nd] ? tree[nd].eval(xs[idx]) : INF;
        if (lo == hi) return res;
        int mid = (lo+hi)/2;
        if (idx <= mid) return min(res, qry(2*nd, lo, mid, idx));
        else return min(res, qry(2*nd+1, mid+1, hi, idx));
    }

    ll query(ll x) {
        int idx = lower_bound(xs.begin(), xs.end(), x) - xs.begin();
        return qry(1, 0, n-1, idx);
    }

    int save() { return undo.size(); }
    void restore(int s) {
        while ((int)undo.size() > s) {
            auto [i,l,h] = undo.back();
            tree[i] = l; has[i] = h; undo.pop_back();
        }
    }
};

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    int n; cin >> n;
    vector<int> par(n+1);
    vector<ll> d(n+1), t(n+1), p(n+1), r(n+1);
    vector<ll> cum(n+1, 0), dp(n+1, 0);
    vector<vector<int>> ch(n+1);

    for (int i = 1; i <= n; i++) {
        cin >> par[i] >> d[i] >> t[i] >> p[i] >> r[i];
        if (i > 1) ch[par[i]].push_back(i);
    }
    for (int i = 2; i <= n; i++) cum[i] = cum[par[i]] + d[i];

    // Coordinate-compress transfer values
    vector<ll> vals;
    for (int i = 2; i <= n; i++) vals.push_back(t[i]);
    if (vals.empty()) vals.push_back(1);

    LiChao lct;
    lct.init(vals);

    // Insert root line: slope=0, intercept=receive[1]
    int sv0 = lct.save();
    lct.insert({0, r[1]});

    // Iterative DFS with rollback
    struct F { int node, ci, sv; };
    vector<F> stk;
    stk.push_back({1, 0, sv0});

    while (!stk.empty()) {
        auto& f = stk.back();
        if (f.ci < (int)ch[f.node].size()) {
            int c = ch[f.node][f.ci++];
            dp[c] = t[c] * cum[c] + p[c] + lct.query(t[c]);
            int sv = lct.save();
            lct.insert({-cum[c], r[c] + dp[c]});
            stk.push_back({c, 0, sv});
        } else {
            lct.restore(f.sv);
            stk.pop_back();
        }
    }

    for (int i = 2; i <= n; i++) {
        cout << dp[i];
        if (i < n) cout << " ";
    }
    cout << "\n";
}
```

---

## Flag

| Flag | Value |
|------|-------|
| Challenge | `HTB{5UCC355FU11Y_RU1N3D_████████████████████████}` |

---

## Key Takeaways

- When a DP recurrence has the form `dp[i] = min(a_i * x_j + b_j)`, the **Convex Hull Trick** reduces optimization from O(N^2) to O(N log N)
- On **tree structures**, the active set of lines changes during DFS — a **Li Chao Tree with rollback** handles insert/query/undo in O(log N) each
- **Coordinate compression** on query values keeps memory bounded at O(N) instead of O(max_value)
- The parent constraint `parent[i] < i` provides a natural topological ordering but doesn't prevent chain-like trees, making the naive O(N * depth) approach insufficient
- For competitive programming CTFs, always check if values require 64-bit integers — this problem has answers exceeding 10^10

---

<div align="center">

**Written by MrsNobody**

<img src="../../assets/MrsNobody.png" width="80">

*Hack The Box — Uplink*

</div>

<!-- HTB Uplink Search Keywords -->
<!-- uplink hackthebox, uplink htb, uplink htb writeup, uplink htb walkthrough -->
<!-- convex hull trick, li chao tree, tree dp, dynamic programming on tree -->
<!-- li chao tree with undo, rollback data structure, coordinate compression -->
<!-- minimum cost tree path, shortest path tree ancestors, competitive programming ctf -->
<!-- htb insane coding challenge, hackthebox algorithm challenge, htb coding writeup -->
