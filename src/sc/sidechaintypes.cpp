#include "sc/sidechaintypes.h"
#include "util.h"

////////////////////////////// Custom Config types //////////////////////////////
bool CompressedFieldElementConfig::isBitsLenghtValid()
{
    //TENTATIVE IMPLEMENTATION, BEFORE ACTUAL ONE
    return (nBits > 0);
}

CompressedFieldElementConfig::CompressedFieldElementConfig(int32_t nBitsIn): CustomFieldConfig(), nBits(nBitsIn)
{
    if (!isBitsLenghtValid())
        throw std::invalid_argument("CompressedFieldElementConfig size must be strictly positive");
}

int32_t CompressedFieldElementConfig::getBitSize() const
{
    //TENTATIVE IMPLEMENTATION, BEFORE ACTUAL ONE
    return nBits;
}

//----------------------------------------------------------------------------------
bool CompressedMerkleTreeConfig::isTreeHeightValid() {
    //TENTATIVE IMPLEMENTATION, BEFORE ACTUAL ONE
    return ((treeHeight >= 0) && (treeHeight < MAX_TREE_HEIGHT));
}

CompressedMerkleTreeConfig::CompressedMerkleTreeConfig(int32_t treeHeightIn): CustomFieldConfig(), treeHeight(treeHeightIn)
{
	if (!isTreeHeightValid())
        throw std::invalid_argument(
            std::string("CompressedMerkleTreeConfig height=" + std::to_string(treeHeight) +
            ", must be in the range [0, ") + std::to_string(MAX_TREE_HEIGHT) + std::string(")"));
}

int32_t CompressedMerkleTreeConfig::getBitSize() const
{
    //TENTATIVE IMPLEMENTATION, BEFORE ACTUAL ONE
    int nBytes = (treeHeight == -1)? 0: 1 << treeHeight;
    return nBytes * CHAR_BIT;
}


////////////////////////////// Custom Field types //////////////////////////////
CustomField::CustomField(const std::vector<unsigned char>& rawBytes)
    :vRawField(rawBytes) {};

//----------------------------------------------------------------------------------------
CompressedFieldElement::CompressedFieldElement(const std::vector<unsigned char>& rawBytes)
    :CustomField(rawBytes) {}

CompressedFieldElement& CompressedFieldElement::operator=(const CompressedFieldElement& rhs)
{
    *const_cast<std::vector<unsigned char>*>(&vRawField) = rhs.vRawField;
    return *this;
}

void CompressedFieldElement::InitFieldElement() const
{
    if (scFieldElement.IsNull())
    {
        if (vRawField.size() > scFieldElement.size())
        {
            LogPrint("sc", "%s():%d - Error: Wrong size: rawData[%d]>fieldElement[%d]\n", 
                __func__, __LINE__, vRawField.size(), scFieldElement.size());
            throw std::invalid_argument(
                std::string("Wrong size: rawData[" + std::to_string(vRawField.size()) + "] > fieldElement[" +
                std::to_string(scFieldElement.size()) + "]"));
        }
        // pad with zeroes, must have the same size for the internal repr
        std::vector<unsigned char> temp(vRawField);
        temp.resize(scFieldElement.size(), 0x0);
        *const_cast<libzendoomc::ScFieldElement*>(&scFieldElement) = libzendoomc::ScFieldElement(temp); // TODO
    }
}

const libzendoomc::ScFieldElement& CompressedFieldElement::GetFieldElement() const
{
    InitFieldElement();
    return scFieldElement;
}

#ifdef BITCOIN_TX
bool CompressedFieldElement::IsValid() const { return true; }
#else
bool CompressedFieldElement::IsValid() const
{
    InitFieldElement();
    if (scFieldElement.IsNull())
        return false;

    return libzendoomc::IsValidScFieldElement(scFieldElement);
};
#endif

bool CompressedFieldElement::checkCfg(const CustomFieldConfig& cfg) const
{
    int rem = 0;
    int bytes = getBytesFromBits(cfg.getBitSize(), rem);

    if (vRawField.size() != bytes )
    {
        LogPrint("sc", "%s():%d - ERROR: wrong size: data[%d] != cfg[%d]\n", 
            __func__, __LINE__, vRawField.size(), cfg.getBitSize());
        return false;
    }

    if (rem)
    {
        // check null bits in the last byte are as expected
        unsigned char lastByte = vRawField.back();
        int numbOfZeroBits = getTrailingZeroBitsInByte(lastByte);
        if (numbOfZeroBits < (CHAR_BIT - rem))
        {
            LogPrint("sc", "%s():%d - ERROR: wrong number of null bits in last byte[0x%x]: %d vs %d\n", 
                __func__, __LINE__, lastByte, numbOfZeroBits, (CHAR_BIT - rem));
            return false;
        }
    }

    return true;
};

//----------------------------------------------------------------------------------
CompressedMerkleTree::CompressedMerkleTree(const std::vector<unsigned char>& rawBytes)
    :CustomField(rawBytes) {}

CompressedMerkleTree& CompressedMerkleTree::operator=(const CompressedMerkleTree& rhs)
{
    *const_cast<std::vector<unsigned char>*>(&vRawField) = rhs.vRawField;
    return *this;
}

void CompressedMerkleTree::CalculateMerkleRoot() const
{
    /*
     *  TODO this is a dummy implementation, useful just for running preliminary tests
     *  In the final version using rust lib the steps to cover would be:
     *
     *   1. Reconstruct MerkleTree from the compressed raw data of vRawField
     *   2. Check for the MerkleTree validity
     *   3. Calculate and store the root hash.
     */

    if (merkleRoot.IsNull())
    {
        if (vRawField.size() > merkleRoot.size())
        {
            LogPrint("sc", "%s():%d - ERROR: wrong size: rawData[%d] > mklRoot[%d]\n", 
                __func__, __LINE__, vRawField.size(), merkleRoot.size());
            throw std::invalid_argument(
                std::string("Wrong size: rawData[" + std::to_string(vRawField.size()) + "] > mklRoot[" +
                std::to_string(merkleRoot.size()) + "]"));
        }
        // pad with zeroes, must have the same size for the internal fe repr
        std::vector<unsigned char> temp(vRawField);
        temp.resize(merkleRoot.size(), 0x0);
        *const_cast<libzendoomc::ScFieldElement*>(&merkleRoot) = libzendoomc::ScFieldElement(temp); // TODO
    }
}

const libzendoomc::ScFieldElement& CompressedMerkleTree::GetFieldElement() const
{
    CalculateMerkleRoot();
    return merkleRoot;
}

bool CompressedMerkleTree::IsValid() const
{
    CalculateMerkleRoot();
    if (merkleRoot.IsNull())
        return false;

    // TODO something like libzendoomc::IsValidScFieldElement() or exactly this?? In this case we can move this to base   
    return true;
}

bool CompressedMerkleTree::checkCfg(const CustomFieldConfig& cfg) const
{
    int rem = 0;
    int bytes = getBytesFromBits(cfg.getBitSize(), rem);

    if (vRawField.size() > bytes )
    {
        LogPrint("sc", "%s():%d - ERROR: mklTree wrong size: data[%d] > cfg[%d]\n", 
            __func__, __LINE__, vRawField.size(), cfg.getBitSize());
        return false;
    }
    return true;
}
////////////////////////// End of Custom Field types ///////////////////////////