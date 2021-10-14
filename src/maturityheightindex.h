#include "uint256.h"

struct CMaturityHeightIteratorKey {
    int blockHeight;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(blockHeight);
    }

    CMaturityHeightIteratorKey(int height) {
        blockHeight = height;
    }

    CMaturityHeightIteratorKey() {
        SetNull();
    }

    void SetNull() {
        blockHeight = 0;
    }
};

struct CMaturityHeightKey {
    int blockHeight;
    uint256 certId;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(blockHeight);
        READWRITE(certId);       
    }

    CMaturityHeightKey(int height, uint256 hash) {
        blockHeight = height;
        certId = hash;
    }

    CMaturityHeightKey() {
        SetNull();
    }

    void SetNull() {
        blockHeight = 0;
        certId.SetNull();
    }
};

//This is needed because the CLevelDBBatch.Write requires 2 arguments (key, value)
struct CMaturityHeightValue {
    char dummy;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(dummy);
    }

    CMaturityHeightValue (char value) {
        dummy = value;
    }

    CMaturityHeightValue() {
        SetNull();
    }

    void SetNull() {
        dummy = '0';
    }

    bool IsNull() const {
        return dummy == '0';
    }
};