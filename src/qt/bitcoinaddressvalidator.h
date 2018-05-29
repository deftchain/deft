// Copyright (c) 2011-2014 The Deft developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BITCOINADDRESSVALIDATOR_H
#define BITCOIN_QT_BITCOINADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class DeftAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit DeftAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Deft address widget validator, checks for a valid bitcoin address.
 */
class DeftAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit DeftAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // BITCOIN_QT_BITCOINADDRESSVALIDATOR_H
