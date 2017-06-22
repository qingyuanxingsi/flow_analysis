# -*- coding:utf-8 -*-

"""
Longest common substring algorithm
"""


def longest_common_substring(s1, s2):
    m = [[0] * (1 + len(s2)) for i in range(1 + len(s1))]
    longest, x_longest = 0, 0
    for x in range(1, 1 + len(s1)):
        for y in range(1, 1 + len(s2)):
            if s1[x - 1] == s2[y - 1]:
                m[x][y] = m[x - 1][y - 1] + 1
                if m[x][y] > longest:
                    longest = m[x][y]
                    x_longest = x
            else:
                m[x][y] = 0
    score = 2 * longest / (len(s1) + len(s2))
    return longest, score, s1[x_longest - longest: x_longest]


"""
Longest common subsequence algorithm
"""


def LCS(X, Y):
    m = len(X)
    n = len(Y)
    # An (m+1) times (n+1) matrix
    C = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if X[i - 1] == Y[j - 1]:
                C[i][j] = C[i - 1][j - 1] + 1
            else:
                C[i][j] = max(C[i][j - 1], C[i - 1][j])
    score = 2 * C[m][n] / (m + n)
    return C, C[m][n], score


def backTrack(C, X, Y, i, j):
    if i == 0 or j == 0:
        return ""
    elif X[i - 1] == Y[j - 1]:
        return backTrack(C, X, Y, i - 1, j - 1) + X[i - 1]
    else:
        if C[i][j - 1] > C[i - 1][j]:
            return backTrack(C, X, Y, i, j - 1)
        else:
            return backTrack(C, X, Y, i - 1, j)


def backTrackAll(C, X, Y, i, j):
    if i == 0 or j == 0:
        return set([""])
    elif X[i - 1] == Y[j - 1]:
        return set([Z + X[i - 1] for Z in backTrackAll(C, X, Y, i - 1, j - 1)])
    else:
        R = set()
        if C[i][j - 1] >= C[i - 1][j]:
            R.update(backTrackAll(C, X, Y, i, j - 1))
        if C[i - 1][j] >= C[i][j - 1]:
            R.update(backTrackAll(C, X, Y, i - 1, j))
        return R


X = "AATCC"
Y = "ACACG"
m = len(X)
n = len(Y)
C, lcs_len, score = LCS(X, Y)
print(lcs_len)
print(score)

print("Some LCS: '%s'" % backTrack(C, X, Y, m, n))
print("All LCSs: %s" % backTrackAll(C, X, Y, m, n))
