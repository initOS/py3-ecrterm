"""
TLV Container Format.

    TAG FIELD:
        # first byte:
        # b8,b7: class visibility
        # b6: data object constructed?
        # b5-b2: tag number.
        # b1: if 1, continue at next byte.

        # next byte:
        b8: last byte?
        ... number.

    LENGTH:
        # b8 if 0, length is a 7 bit number.
        # b8 if 1, this byte only codes how many follow.
"""
from ecrterm.packets.bmp import BMP

class TLVFactory(BMP):
    @classmethod
    def FormatTLVTag(cls, tag=0x06):
        class SomeTLVTag(TLV_TAG):
            _id = tag
        return SomeTLVTag


class TLV_TAG(TLVFactory):
    _id = 0x06

    def __repr__(self):
        return "TLV %s, tag: 0x%X, data: %s" % (self._key, self._id, self._data)

    @classmethod
    def tag(cls, tag):
        """
        Transforms a number into a TLV Tag ,returns list of bytes.
        """
        # FIXME Longer tags 
        tag = tag & 0x1F
        return [tag, ]

    @classmethod
    def length(cls, length):
        """
        Transforms a number into a TLV Length ,returns list of bytes.
        """
        if length >= 0x80:  # 128 or more...
            # we need more than 1 byte.
            # lets see if we need only 2:
            if length > 0xff:  # 256 or more..
                # 0x82 followed by high byte and low byte.
                hb = (length & 0xFF00) >> 8
                lb = length & 0xFF
                return [0x80 + 2, hb, lb]
            else:
                return [0x80 + 1, length]
        else:
            # one byte is enough.
            return [length, ]

    def parse(self, data):
        # First find out tag
        if data[0] & 0x1F == 0x1F: # >1-byte tag
            tag_length = 2
            data_index = 1
            tag = data[data_index] & 0x7F
            while ((data[data_index] & 0x80) >> 7) != 0:
                tag = (tag << 7) | (data[data_index] & 0x7F)
                data_index += 1
                tag_length += 1

        else: # 1-byte length
            tag = data[0] & 0x1F
            tag_length = 1

        # Now parse length 
        data = data[tag_length:]
        length_length = 1
        l1 = data[0]
        if l1 > 0x80: # >1-byte length
            bytes = max(2, l1 - 0x80)
            if bytes == 2:
                # hb, lb
                hb = data[1]
                lb = data[2]
                length += (hb << 8) + lb
            elif bytes == 1:
                # one byte.
                length = data[1]
            length_length += bytes
        else:
            length = l1
        data = data[length_length:]

        self._id = tag
        self._data = data[:length]
        return data[length:]


    def dump(self):  # dump the bytes.
        """
            dumps the bytes of the TLV as one list.
            the minimum length of the length header can be set with self.LL
        """
        ret = []
        ret += TLV_TAG.tag(self._id)
        lines = [self._data, ]
        for line in lines:
            length = TLV_TAG.length(len(line))
            if len(line) == 0:
                ret += length
            elif isinstance(line, list):
                ret += length + line
            else:
                raise TypeError(
                    "Line has unsupported type in TLV: %s" % type(line))
        return ret



TLV_TAGS = {
    0x12: (TLVFactory.FormatTLVTag(0x12), 'tlv12', 'TLV12 line width'),
}

TAGS_TLV_ARGS = {}
test_keys_TLV = []
for key in TLV_TAGS.keys():
    klass, k, info = TLV_TAGS[key]
    test_keys_TLV += [k]
    TAGS_TLV_ARGS[k] = (key, klass, info)



class TLV(BMP):
    _id = 0x06
    _tlvs = []

    def __init__(self, data=None):
        if data:
            tlvs = []
            for k, v in data.items():
                try:
                    None
                    key, klass, info = TAGS_TLV_ARGS.get(k, (None, None, None))
                except Exception:
                    pass
                if klass:
                    tlv = klass(v)
                    tlv._key = k
                    tlv._descr = info
                    tlvs += [tlv]
            self._tlvs = tlvs

    def __repr__(self):
        return "Bitmap %s, id: 0x%X, data: %s, tlvs: %s" % (self._key, self._id, self._data, self._tlvs)

    @classmethod
    def length(cls, length):
        """
        Transforms a number into a TLV Length ,returns list of bytes.
        """
        if length >= 0x80:  # 128 or more...
            # we need more than 1 byte.
            # lets see if we need only 2:
            if length > 0xff:  # 256 or more..
                # 0x82 followed by high byte and low byte.
                hb = (length & 0xFF00) >> 8
                lb = length & 0xFF
                return [0x80 + 2, hb, lb]
            else:
                return [0x80 + 1, length]
        else:
            # one byte is enough.
            return [length, ]

    def parse(self, data):
        # first find out length
        l1 = data[0]
        if l1 > 0x80:
            bytes = max(2, l1 - 0x80)
            if bytes == 2:
                # hb, lb
                hb = data[1]
                lb = data[2]
                length = (hb << 8) + lb
                data = data[3:]
            elif bytes == 1:
                # one byte.
                length = data[1]
                data = data[2:]
        else:
            length = l1
            data = data[1:]

        # then parse all TLV containers in data[:length]
        tlv_data = data[:length]
        while len(tlv_data) > 0:
            tlv = TLV_TAG()
            tlv_data = tlv.parse(tlv_data)
            self._tlvs.append(tlv)
        
        return tlv_data

    def dump(self):  # dump the bytes.
        """
            dumps the bytes of the TLV as one list.
        """
        ret = [self._id]
        if len(self._tlvs) > 0: #dump all TLV packets
            tlv_data = []
            for tlv in self._tlvs:
                tlv_data += tlv.dump()
            length = TLV.length(len(tlv_data))
            ret += length + tlv_data
        else: #empty
            ret += [0]
        return ret


if __name__ == '__main__':
    from pprint import pprint
    pprint(TAGS_TLV_ARGS)
    if len(test_keys_TLV) != len(set(test_keys_TLV)):
        print("#" * 80)
        raise Exception("Duplicate Keys in TAGS_TLV_ARGS, please check.")
