
from struct import *
from array import *
from defines import DEFINES


class ElementBase(object):

  #MleDataSha256HashFormatString    = "<32B"
  #MleDataSha256HashFormatString    = "<32B"
  #MleDataSha384HashFormatString    = "<48B"
  #MleDataSha512HashFormatString    = "<64B"
  
  def __init__(self):
    pass


  # alg is a string that specifies hash algorithm
  # hash is the array of bytes of the hash value
  #
  def packHash(self, alg, hash):
    #hashFormatString = "<" + str(DEFINES.DIGEST_SIZE[alg]) + "B"  # Build the pack format string for different hash algorithms
    #hashData = pack(hashFormatString, array('B', hash))
    #print "DEBUG: hash format string = "+ HashFormatString
    
    # Check hash size vs. expected size for specified algorithm
    hashData = None
    if (DEFINES.DIGEST_SIZE[alg] == len(hash)):
      b = bytes()
      hashData = b.join(pack('B', val) for val in hash)
    else:
      print ("ERROR: Hash buffer size %d does not match required size for %s" %(len(hash), alg))

    return hashData



if __name__ == "__main__":
  sha256data = [val for val in range(DEFINES.DIGEST_SIZE['SHA256'])]
  e = ElementBase();
  joinedHash = e.packHash('SHA256', sha256data)

  if (joinedHash is not None):
    print "SUCCESS"
  else:
    print "FAILED"

  print joinedHash
