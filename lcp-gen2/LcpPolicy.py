#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

# TXT Policy Generator Tool
# LcpPolicy and LcpPolicyData Classes - LCP_POLICY and LCP_POLICY_DATA File Structure
#

from defines import DEFINES
from ElementBase import *


class LCP_POLICY2( object ):
  """ LCP_POLICY2 Class"""

  #
  # LCP_POLICY2 struct
  #
  def __init__( self ):
    """__init__() - LCP_POLICY2 class constructor"""
    #self.Version                   # UINT16 - from pdef.PolVersion = 0x0300
    self.VersionMajor = 03          # UINT8
    self.VersionMinor = 00          # UINT8
    self.HashAlg = 00               # UINT16 - TPM_ALG_* from pdef.HashAlg
    self.PolicyType = 00            # UINT8 - 0=LIST, 1=ANY  - from pdef.PolicyType
    self.SINITMinVersion = 00       # UINT8 - from pdef.SinitMinVersion
    self.DataRevocationCounters = [0,0,0,0,0,0,0,0]  # UINT16  DataRevocationCounters[MAX_LISTS] Default is 0's
                                                     #  from pdef.DataRevocationCounters[]
    self.PolicyControl =  0         # UINT32  Encoding of (NPW, PCR17, Force PO), from pdef.PolicyControl
    self.MaxSinitMinVer = 0         # UINT8  PO only, reserved for PS
    self.MaxBiosAcMinVer = 0        # UINT8  PO only, reserved for PS
    self.LcpHashAlgMask = 0         # UINT16 HashMask for LCP eval.
    self.LcpSignAlgMask = 0
    self.AuxHashAlgMask = 0         # UINT16 Hash Mask for Auto-Promotion
    # Reserved                      # UINT16
    self.PolicyHash = []

    #self.PolicyHashSha256     = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    #
    # The raw [ie binary] format LCP_POLICY.pol file is generated using struct.pack
    # based on the format string below.
    #
    # 'struct' module format string for a LCP_POLICY Structure
    #     where: B = UINT8, H = UINT16, L = UINT32
    #           '<' means Little Endian, std size, no alignment between fields
    #self.LcpPolicyFormatStringSha256 = "<BBHBB8HLBBHHH32B"   # for SHA256 policy hash
    self.LcpPolicyFormatStringNoHash = "<BBHBB8HLBBHLHH"
    self.LcpPolicyFormatString       = "<BBHBB8HLBBHHH"      # for policy hash - Hash added separately


class LCP_POLICY_DATA2( object):
  """LCP_POLICY_DATA2 class"""

  def __init__(self):
    """__init__() - LCP_POLICY_DATA2 class constructor"""

    self.FileSignature = "Intel(R) TXT LCP_POLICY_DATA\0\0\0\0"    # char [32]
    #self.Reserved[3]             # UINT8 [3]
    self.NumLists = 0             # UINT8
                                  # LCP_POLICY_LIST PolicyLists[NumLists];
    self.PolicyLists = {'0': LCP_POLICY_LIST2(), '1': LCP_POLICY_LIST2(),
                        '2': LCP_POLICY_LIST2(), '3': LCP_POLICY_LIST2(),
                        '4': LCP_POLICY_LIST2(), '5': LCP_POLICY_LIST2(),
                        '6': LCP_POLICY_LIST2(), '7': LCP_POLICY_LIST2()}

    # 'struct' module format string for a LCP_POLICY_DATA2 Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.HeaderFormatString       = "<32c3BB"   # same as LCP_POLICY_DATA header above

  def pack(self):
    """packLcpPolicyDataHeader"""

    #print("packLcpPolicyDataHeader") # DBGDBG
    #
    # LCP_POLICY_DATA Header
    #     CHAR8 FileSignature[32];
    #     UINT8 Reserved[3];
    #     UINT8 NumLists;
    return( pack(self.HeaderFormatString,
                self.FileSignature[0],self.FileSignature[1],
                self.FileSignature[2],self.FileSignature[3],
                self.FileSignature[4],self.FileSignature[5],
                self.FileSignature[6],self.FileSignature[7],
                self.FileSignature[8],self.FileSignature[9],
                self.FileSignature[10],self.FileSignature[11],
                self.FileSignature[12],self.FileSignature[13],
                self.FileSignature[14],self.FileSignature[15],
                self.FileSignature[16],self.FileSignature[17],
                self.FileSignature[18],self.FileSignature[19],
                self.FileSignature[20],self.FileSignature[21],
                self.FileSignature[22],self.FileSignature[23],
                self.FileSignature[24],self.FileSignature[25],
                self.FileSignature[26],self.FileSignature[27],
                self.FileSignature[28],self.FileSignature[29],
                self.FileSignature[30],self.FileSignature[31],
                0,0,0,
                self.NumLists)
          )


class LCP_RSA_SIGNATURE( object ):
  """LCP_RSA_SIGNATURE class"""

  def __init__(self):
    """__init__() - LCP_SIGNATURE class constructor"""

    self.RevocationCounter    = 0                # UINT16
    self.PubkeySize           = 2048             # UINT16 - key sizes are 1024, 2048 and 3072 bits. Default=2048
    self.PubkeyValue          = ""               # UINT8 PubkeyValue[PubkeySize]
    self.SigBlock             = ""               # UINT8 SigBlock[PubkeySize];   - as a binary string

    self.LcpRsaSignatureHdrFormatString  = "<HH"          # just the 1st 2 fields, other's size depends on KeySize

  def pack(self):
    """packLcpRsaSignatureHeader"""

    return( pack(self.LcpRsaSignatureHdrFormatString,
                self.RevocationCounter, self.PubkeySize/8)
            )


class LCP_ECC_SIGNATURE( object ):
  """LCP_SIGNATURE2 class"""

  def __init__(self):
    """__init__() - LCP_SIGNATURE class constructor"""

    self.RevocationCounter    = 0                # UINT16
    self.PubkeySize           = 256              # UINT16
    self.Reserved             = 0                # UINT32
    self.Qx                   = ""               # UINT8 x coordinate Public Key [PubkeySize]
    self.Qy                   = ""               # UINT8 y coordinate Public Key [PubkeySize]
    self.r                    = ""               # UINT8 r component of Signature
    self.s                    = ""               # UINT8 y component of Signature

    self.LcpEccSignatureHdrFormatString  = "<HHL"           # just the 1st 2 fields, other's size depends on KeySize

  def pack(self):
    """packLcpEccSignatureHeader - pack this LCP_ECC_SIGNATURE object except its SigBlock member and return the packed data"""

    # Note - The public key size in the pdef is the number of bits (1024, 2048, 3072)
    #        while LCP_SIGNATURE.PublicKeySize is the number if bytes, hence the /8 below
    return( pack(self.LcpEccSignatureHdrFormatString,
                self.RevocationCounter, self.PubkeySize/8, self.Reserved)
            )


class LCP_SIGNATURE2( object ):
  """LCP_SIGNATURE2 class"""

  def __init__(self):
    """__init__() - LCP_SIGNATURE class constructor"""

    self.RevocationCounter    = 0                # UINT16
    self.PubkeySize           = 2048             # UINT16 - key sizes are 1024, 2048 and 3072 bits. Default=2048
    self.PubkeyValue          = ""               # UINT8 PubkeyValue[PubkeySize]
    self.SigBlock             = ""               # UINT8 SigBlock[PubkeySize];   - as a binary string

    self.LcpSignatureHdrFormatString  = "<HH"             # just the 1st 2 fields, other's size depends on KeySize


class LCP_POLICY_LIST2( object ):
  """LCP_POLICY_LIST2 class"""

  def __init__(self):
    """__init__() - LCP_POLICY_LIST class constructor"""

    #self.Version             = 0x0200      # UINT16 - version 2.0
    self.VersionMajor        = 02
    self.VersionMinor        = 01
    self.SigAlgorithm        = 0x10         # UINT16 - one of LCP_POLSALG_*
    self.PolicyElementsSize  = 0            # UINT32
    # There can be 1 element of each type of each hash algorithm
    self.PolicyElements = []  # LCP_POLICY_ELEMENT
    #self.PolicyElements = {0:None, 1:None, 2:None, 3:None,  # LCP_POLICY_ELEMENT
    #                       4:None, 5:None, 6:None, 7:None}
    self.Signature = None                   # LCP_SIGNATURE - either LCP_RSA_SIGNATURE or LCP_ECC_SIGNATURE
                                            #  only included if SigAlgorithm != LCP_POLSALG_NONE

    # 'struct' module format string for a LCP_POLICY_LIST2 Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.HeaderFormatString       = "<BBHL"

  def pack(self):
    """packLcpPolicyListHeader"""

    #print("packLcpPolicyListHeader") # DBGDBG
    # LCP_POLICY_LIST Header
    #     UINT16 Version;                         // 0x0100                   Header
    #     UINT16 SigAlgorithm;                    // one of LCP_POLSALG_*     Header
    #     UINT32 PolicyElementsSize;              //                          Header
    return( pack(self.HeaderFormatString,
                self.VersionMinor, self.VersionMajor,
                self.SigAlgorithm, self.PolicyElementsSize)
            )

#
# LCP_MLE_ELEMENT2
#
class LCP_MLE_ELEMENT2( ElementBase ):
  """LCP_MLE_ELEMENT2 class"""

  def __init__(self):
    """__init__() - LCP_MLE_ELEMENT class constructor"""

    self.ElementSize      = 0                       # UINT32 - header
    self.ElementType      = DEFINES.LCP_POLELT_TYPE_MLE2     # UINT32 - header
    self.PolEltControl    = 0                       # UINT32 - header
    self.SINITMinVersion  = 0                       # UINT8
    # Reserved                                      # UINT8
    self.HashAlg          = 0                       # UINT16
    self.NumHashes        = 0                       # UINT16
    self.Hashes           = []                      # LCP_HASH Hashes[NumHashes]

    # 'struct' module format string for a LCP_MLE_ELEMENT2 Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.MleDataFormatString              = "<LLLBBHH"
    self.MleDataSha256HashFormatString    = "<32B"

  def pack(self):
    """packLcpPolicyMleElement - pack this list's MLE element """
    func = 'packLcpPolicyMleElement'

    print("%s packing MLE hdr" % (func))   # DBGDBG
    
    # Initialize to None to check for supported HashAlg.
    hashAlgName = None
    # reverse lookup of the hash algorithm name(key) for the given HashAlg value
    hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == self.HashAlg)).next()
    if (hashAlgName == None):
      print ("MLE elements with unsupported hash algorithm, aborting build")
      print("%s - build failed, see status bar" % (func))  # DBGDBG
      return

    # pack the element based on its type and return the binary string
    elementData = pack(self.MleDataFormatString,
        self.ElementSize, self.ElementType,
        self.PolEltControl, self.SINITMinVersion, 0,
        self.HashAlg, self.NumHashes)
        
    print("%s PolEltControl=%d, SINITMinVersion=%d" %(func, self.PolEltControl, self.SINITMinVersion))   # DBGDBG
    fileCnt = 0
    while(fileCnt < self.NumHashes):
      print("%s packing MLE hash %d" % (func, fileCnt))   # DBGDBG
      elementData += self.packHash(hashAlgName, self.Hashes[fileCnt])
      fileCnt += 1

    return( elementData )

#
# LCP_STM_ELEMENT2
#
class LCP_STM_ELEMENT2( ElementBase ):
  """LCP_STM_ELEMENT2 class"""

  def __init__(self):
    """__init__() - LCP_STM_ELEMENT class constructor"""

    self.ElementSize      = 0                       # UINT32 - header
    self.ElementType      = DEFINES.LCP_POLELT_TYPE_STM2     # UINT32 - header
    self.PolEltControl    = 0                       # UINT32 - header
    self.HashAlg          = 0                       # UINT16
    self.NumHashes        = 0                       # UINT16
    self.Hashes           = []                      # LCP_HASH Hashes[NumHashes]

    # 'struct' module format string for a LCP_STM_ELEMENT2 Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.StmDataFormatString              = "<LLLHH"
    self.StmDataSha256HashFormatString    = "<32B"

  def pack(self):
    """packLcpPolicyStmElement - pack this list's STM element """
    func = 'packLcpPolicyStmElement'

    print("%s packing STM hdr" % (func))   # DBGDBG

    # Initialize to None to check for supported HashAlg.
    hashAlgName = None
    # reverse lookup of the hash algorithm name(key) for the given HashAlg value
    hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == self.HashAlg)).next()
    if (hashAlgName == None):
      print ("STM elements with unsupported hash algorithm, aborting build")
      print("%s - build failed, see status bar" % (func))  # DBGDBG
      return

    # pack the element based on its type and return the binary string
    elementData = pack(self.StmDataFormatString,
        self.ElementSize, self.ElementType, self.PolEltControl,
        self.HashAlg, self.NumHashes)
        
    print("%s PolEltControl=%d" %(func, self.PolEltControl))   # DBGDBG
    fileCnt = 0
    while(fileCnt < self.NumHashes):
      print("%s packing STM hash %d" % (func, fileCnt))   # DBGDBG
      elementData += self.packHash(hashAlgName, self.Hashes[fileCnt])
      fileCnt += 1

    return( elementData )

#
# LCP_PCONF_ELEMENT2
#
class LCP_PCONF_ELEMENT2( ElementBase ):
  """LCP_PCONF_ELEMENT2 class"""

  def __init__(self):
    """__init__() - LCP_PCONF_ELEMENT class constructor"""

    self.ElementSize      = 0                             # UINT32 - header
    self.ElementType      = DEFINES.LCP_POLELT_TYPE_PCONF2 # UINT32 - header
    self.PolEltControl    = 0                             # UINT32 - header
    self.HashAlg          = 0                             # UINT16
    self.NumPCRInfos      = 0                             # UINT16
    self.PCRInfos         = []                            # TPMS_QUOTE_INFO PCRInfos[NumPCRInfos]

    # 'struct' module format string for a LCP_PCONF_ELEMENT2 Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.PconfDataFormatString        = "<LLLHH"    # ElementSize,Type,Ctl,HashAlg,NumPcrInfos
    self.PconfDataSha256FormatString = "<32B"

  def pack(self):
    """packLcpPolicyPconfElement - pack this list's PCONF element """

    func = "packLcpPolicyPconfElement"
    print("%s packing PCONF hdr" % (func))   # DBGDBG
    
    # Initialize to None to check for supported HashAlg.
    hashAlgName = None
    # reverse lookup of the hash algorithm name(key) for the given HashAlg value
    hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == self.HashAlg)).next()
    if (hashAlgName == None):
      print ("PCONF elements with unsupported hash algorithm, aborting build")
      print("%s - build failed, see status bar" % (func))  # DBGDBG
      return
      
    # pack the element based on its type and return the binary string
    elementData = pack(self.PconfDataFormatString,
        self.ElementSize, self.ElementType,
        self.PolEltControl, self.HashAlg,
        self.NumPCRInfos)

    numPcrInfos = 0
    while(numPcrInfos < self.NumPCRInfos):
      print("%s packing Pconf PcrInfo %d" %(func, numPcrInfos))   # DBGDBG
      elementData += self.PCRInfos[numPcrInfos].pack()
      numPcrInfos += 1
      # end of numPcrInfo while

    return( elementData )


#
# TPMS_QUOTE_INFO
#
class TPMS_QUOTE_INFO( ElementBase ):
  """TPMS_QUOTE_INFO class"""

  def __init__(self):
    """__init__() - TPMS_QUOTE_INFO class constructor"""

    self.pcrSelect         = TPML_PCR_SELECTION()      # TPML_PCR_SELECTION	pcrSelect
    self.pcrDigest         = TPM2B_DIGEST()           # UINT8
    
    # 'struct' module format string for a TPMS_QUOTE_INFO Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.TpmsQuoteInfoFormatString = ">LHB3BH"   # TPMS_QUOTE_INFO: count,hash,sizeOfSelect,pcrSelect[],bufferSize
    
  def pack(self):
    # TPMS_QUOTE_INFO is big endian so packing TPML_PCR_SELECTION and TPM2B_DIGEST here,
    # in case those can be used elsewhere as little endian.

    func = "packLcpPolicyPconfElement_tpms_quote_info"
    thisTpmlPcrSelection = self.pcrSelect
    thisTpm2bDigest      = self.pcrDigest
    thisTpmsPcrSelection = thisTpmlPcrSelection.pcrSelections
    thisBuf              = thisTpm2bDigest.buffer
    #print("packLcpPolicyPconfElement TypeOf: thisPcrInfo.digestAtRelease[0]=%s, _GlobalPcrHash=%s, _GlobalPcrHash[0]=%s" %
    #      (type(thisPcrInfo.digestAtRelease[0]), type(_GlobalPcrHash), type(_GlobalPcrHash[0])))  # DBGDBG

    elementData = pack(self.TpmsQuoteInfoFormatString,
        thisTpmlPcrSelection.count,
        thisTpmsPcrSelection.hash, thisTpmsPcrSelection.sizeOfSelect,
        thisTpmsPcrSelection.pcrSelect[0],
        thisTpmsPcrSelection.pcrSelect[1],
        thisTpmsPcrSelection.pcrSelect[2],
        thisTpm2bDigest.size)

    # pack TPM2B_DIGEST.buffer. this does not verify the size as multiple of hash digest size.
    b = bytes()
    elementData += b.join(pack('B', val) for val in thisBuf)
    
    return( elementData )


#
# TPML_PCR_SELECTION
#
class TPML_PCR_SELECTION( object ):
  """TPML_PCR_SELECTION class"""

  def __init__(self):
    """__init__() - TPML_PCR_SELECTION class constructor"""

    self.count              = 0                       # UINT32	count;	# must be 1 for use in PCONF
    self.pcrSelections      = TPMS_PCR_SELECTION()    # TPMS_PCR_SELECTION	pcrSelections;


#
# TPMS_PCR_SELECTION
#
class  TPMS_PCR_SELECTION( object ):
  """TPMS_PCR_SELECTION class"""

  def __init__(self):
    """__init__() - TPMS_PCR_SELECTION class constructor"""

    self.hash               = 0
    self.sizeOfSelect       = 0x03                    # UINT8	sizeofSelect;
    self.pcrSelect          = [0, 0, 0]               # UINT8 pcrSelect[sizeofSelect];


#
# TPM2B_DIGEST
#
class TPM2B_DIGEST( object ):
  """TPM2B_DIGEST class"""

  def __init__(self):
    """__init__() - TPM2B_DIGEST class constructor"""

    self.size              = 0      # size of buffer  # UINT16
    self.buffer            = []                       # UINT8	buffer[size];
    
    # 'struct' module format string for a TPMS_QUOTE_INFO Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.Tpm2BDigestFormatString = ">H"

  def pack(self):
    elementData = pack(self.Tpm2BDigestFormatString,   # TODO: is this always big endian?
                      self.size)
    b = bytes()
    elementData += b.join(pack('B', val) for val in self.buffer)
  
    return elementData


#
# LCP_SBIOS_ELEMENT2
#
class LCP_SBIOS_ELEMENT2( ElementBase ):
  """LCP_SBIOS_ELEMENT2 class"""

  def __init__(self):
    """__init__() - LCP_SBIOS_ELEMENT class constructor"""

    self.ElementSize    = 0                            # UINT32 - header
    self.ElementType    = DEFINES.LCP_POLELT_TYPE_SBIOS2        # UINT32 - header
    self.PolEltControl  = 0                            # UINT32 - header
    self.HashAlg        = 0                            # UINT16
    #self.Reserved1[2]                                 # UINT8 0, 0
    self.FallbackHash   = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
                                                       # LCP_HASH
    #self.Reserved2                                    # UINT16 0x0000
    self.NumHashes      = 0                            # UINT16
    self.Hashes         = []                           # LCP_HASH Hashes[NumHashes]

    # 'struct' module format string for a LCP_SBIOS_ELEMENT2 Structure
    #     where: B = UINT8, H = UINT16, L = UINT32 c = char
    #           '<' means Little Endian, std size, no alignment between fields
    self.SbiosDataFormatString           = "<LLLHBB"
    self.SbiosDataHashFormatString       = "<HH"
    self.SbiosDataSha256FormatString     = "<LLLHBB32BHH"       # SHA256 fallback hash
    self.SbiosDataSha256HashFormatString = "<32B"

  def pack(self):
    """packLcpPolicySbiosElement - pack this list's SBIOS element """

    func = "packLcpPolicySbiosElement"
    print("%s packing SBIOS hdr" % (func))   # DBGDBG
    
    # Initialize to None to check for supported HashAlg.
    hashAlgName = None
    # reverse lookup of the hash algorithm name(key) for the given HashAlg value
    hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == self.HashAlg)).next()
    if (hashAlgName == None):
      print ("SBIOS elements with unsupported hash algorithm, aborting build")
      print("%s - build failed, see status bar" % (func))  # DBGDBG
      return

    elementData = pack(self.SbiosDataFormatString,
        self.ElementSize, self.ElementType, self.PolEltControl,
        self.HashAlg, 0,0)
        
    # pack the element based on its type and return the binary string
    elementData += self.packHash(hashAlgName, self.FallbackHash)
    
    elementData += pack(self.SbiosDataHashFormatString,
        0, self.NumHashes)

    fileCnt = 0
    while(fileCnt < self.NumHashes):
      print("%s packing SBIOS hash %d" % (func, fileCnt))   # DBGDBG
      elementData += self.packHash(hashAlgName, self.Hashes[fileCnt])
      fileCnt += 1

    return( elementData )


#
# DIGEST ListMeasurements[PDEF.NumLists]
#
class ListMeasurements( object ):
  """ListMeasurements class"""

  def __init__(self):
    """__init__() - ListMeasurements class constructor"""

    # SHA256 - 32 bytes
    self.hashes   = {'0': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                     '1': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                     '2': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                     '3': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                     '4': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                     '5': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                     '6': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                     '7': [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}

