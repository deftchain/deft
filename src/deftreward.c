#include <stdio.h>
#include <stdint.h>

typedef int64_t CAmount;
int nSubsidySlowStartInterval = 5000;
int nSubsidyHalvingInterval = 150000;
static const CAmount COIN = 100000000;

CAmount GetBlockSubsidy(int nHeight)
{
    CAmount nSubsidy = 8.5 * COIN;

    // premine for dev/bounties etc
    if (nHeight == 1) {
        nSubsidy = 250000 * COIN;
        return nSubsidy;
    }

    // slow roll for pow (zcash takes the credit here)
    if (nHeight < nSubsidySlowStartInterval / 2) {
        nSubsidy /= nSubsidySlowStartInterval;
        nSubsidy *= nHeight;
        return nSubsidy;
    } else if (nHeight < nSubsidySlowStartInterval) {
        nSubsidy /= nSubsidySlowStartInterval;
        nSubsidy *= (nHeight+1);
        return nSubsidy;
    }

    int halvings = (nHeight - (nSubsidySlowStartInterval / 2)) / nSubsidyHalvingInterval;

    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    nSubsidy >>= halvings;
    return nSubsidy;
}

int main()
{
    int nHeight;
    double oldb = 0;
    double balance, mcap;

    for (nHeight = 1; nHeight < 3000000; nHeight++) {
       balance = GetBlockSubsidy(nHeight) / 100000000.0;
       mcap += balance;
       if (oldb != balance)
         printf("%8d           %0.8f           %0.8f\n", nHeight, balance, mcap);
       oldb = balance;
    }

    return 0;
}
