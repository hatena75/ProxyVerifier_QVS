let delegationCert = null;
let delegationPrivateKey = null;

function setDelegationCert(newValue) {
    delegationCert = newValue;
}

function getDelegationCert() {
    return delegationCert;
}

function setDelegationPrivateKey(newValue) {
    delegationPrivateKey = newValue;
}

function getDelegationPrivateKey() {
    return delegationPrivateKey;
}

module.exports = { setDelegationCert, getDelegationCert, setDelegationPrivateKey, getDelegationPrivateKey };