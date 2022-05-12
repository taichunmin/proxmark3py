from serial.serialutil import to_bytes
import serial
import re

PM3CMD = {
    'ACK': 0x00ff,
    'HF_ISO14443A_READER': 0x0385,
    'HF_MIFARE_EML_MEMGET': 0x0603,
    'HF_MIFARE_EML_MEMSET': 0x0602,
    'HF_MIFARE_READBL': 0x0620,
    'HF_MIFARE_READSC': 0x0621,
    'HF_MIFARE_SIMULATE': 0x0610,
    'NACK': 0x00fe,
    'UNKNOWN': 0xffff,
    'WTX': 0x0116,
}


class Packet(bytearray):
    '''A wrapper class of bytearray with customized methods'''

    def __str__(self):
        '''String representation of Packet'''
        return '{name}(len={len}): {dump}'.format(name=self.__class__.__name__, len=len(self), dump=' '.join(re.findall(r'.{2}', self.hex())))

    def merge(*bufs):
        if len(bufs) < 2:
            return bufs[0] if len(bufs) else Packet()
        size = sum([len(buf) for buf in bufs])
        merged = Packet(size)
        pos = 0
        for buf in bufs:
            merged[pos: pos + len(buf)] = buf
            pos += len(buf)
        return merged

    def subarray(self, start, end=None):
        return Packet(self[start: end])

    def get_intn(self, offset, little=True, size=1, signed=False):
        return int.from_bytes(
            self[offset: offset + size],
            'little' if little else 'big',
            signed=signed)

    def get_uint8(self, offset, little=True):
        return self.get_intn(offset, little, 1, False)

    def get_uint16(self, offset, little=True):
        return self.get_intn(offset, little, 2, False)

    def get_uint24(self, offset, little=True):
        return self.get_intn(offset, little, 3, False)

    def get_uint32(self, offset, little=True):
        return self.get_intn(offset, little, 4, False)

    def get_uint64(self, offset, little=True):
        return self.get_intn(offset, little, 8, False)

    def get_int8(self, offset, little=True):
        return self.get_intn(offset, little, 1, True)

    def get_int16(self, offset, little=True):
        return self.get_intn(offset, little, 2, True)

    def get_int24(self, offset, little=True):
        return self.get_intn(offset, little, 3, True)

    def get_int32(self, offset, little=True):
        return self.get_intn(offset, little, 4, True)

    def get_int64(self, offset, little=True):
        return self.get_intn(offset, little, 8, True)

    def set_intn(self, offset, newVal, little=True, size=1, signed=False):
        self[offset: offset +
             size] = newVal.to_bytes(size, 'little' if little else 'big', signed=signed)

    def set_uint8(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 1, False)

    def set_uint16(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 2, False)

    def set_uint24(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 3, False)

    def set_uint32(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 4, False)

    def set_uint64(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 8, False)

    def set_int8(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 1, True)

    def set_int16(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 2, True)

    def set_int24(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 3, True)

    def set_int32(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 4, True)

    def set_int64(self, offset, newVal, little=True):
        return self.set_intn(offset, newVal, little, 8, True)


class PacketResponseNG:
    def __init__(self, packet: Packet):
        if not isinstance(packet, Packet):
            raise ValueError('packet should be Packet')
        # print(packet)
        self.packet = packet
        self.data = packet.subarray(10 if self.ng else 34, len(packet) - 2)

    def __len__(self):
        return len(self.packet)

    @property
    def ng(self):
        return (self.packet.get_uint8(5) & 0x80) > 0

    @property
    def status(self):
        return self.packet.get_int16(6)

    @property
    def cmd(self):
        return self.packet.get_uint16(8)

    @property
    def crc(self):
        return self.packet.get_uint16(len(self.packet) - 2)

    def getArg(self, index):
        return self.packet.get_uint64(10 + (index << 3))


class PacketResponseOLD:
    def __init__(self, packet: Packet):
        if not isinstance(packet, Packet):
            raise ValueError('packet should be Packet')
        self.packet = packet
        self.data = packet.subarray(32)

    @property
    def cmd(self):
        return self.packet.get_uint16(0)

    def getArg(self, index):
        return self.packet.get_uint64(8 + (index << 3))


class Proxmark3Adapter(serial.Serial):
    def __init__(self, *args):
        super().__init__(*args)

    def sendCommandNG(self, cmd, data: Packet = None, ng=True):
        if data and not isinstance(data, Packet):
            raise ValueError('data should be Packet')
        datalen = len(data) if data else 0
        if datalen > 512:
            raise ValueError('len(data) > 512')
        packet = Packet(datalen + 10)
        packet[0:4] = b'PM3a'
        packet.set_uint16(4, datalen + (0x8000 if ng else 0))
        packet.set_uint16(6, cmd)
        if data:
            packet[8: datalen + 8] = data
        packet[-2:] = b'a3'
        if not self.is_open:
            self.open()
        # print(packet)
        self.write(packet)

    def sendCommandMix(self, cmd, arg=[], data: Packet = None):
        if data and not isinstance(data, Packet):
            raise ValueError('data should be Packet')
        datalen = len(data) if data else 0
        if datalen > 488:
            raise ValueError('len(data) > 488')
        packet = Packet(datalen + 24)
        if data:
            packet[24:] = data
        for i in range(3):
            packet.set_uint64(i << 3, arg[i] if i in arg else 0)
        self.sendCommandNG(cmd, packet, False)

    def readResp(self):
        if not self.is_open:
            self.open()
        pre = Packet(self.read(10))
        if pre[0:4] == b'PM3b':
            return PacketResponseNG(Packet.merge(pre, self.read((pre.get_uint16(4) & 0x7fff) + 2)))
        else:
            return PacketResponseOLD(Packet.merge(pre, self.read(534)))

    def waitRespTimeout(self, cmd, timeout=2500):
        backup = self.get_settings()
        self.apply_settings({timeout: (timeout + 100) / 1000})
        try:
            while True:
                resp = self.readResp()
                if cmd == PM3CMD['UNKNOWN'] or resp.cmd == cmd:
                    return resp
                if resp.cmd == PM3CMD['WTX'] and len(resp.data) == 2:
                    wtx = resp.data.get_uint16(0)
                    if wtx >= 0xffff:
                        continue
                    self.apply_settings(
                        {timeout: (timeout + wtx + 100) / 1000})
        finally:
            self.apply_settings(backup)


class Proxmark3:
    def __init__(self, adapter: Proxmark3Adapter):
        self.adapter = adapter

    def hf14a_disconnect(self):
        self.adapter.sendCommandMix(PM3CMD['HF_ISO14443A_READER'])

    def mf_eset(self, data: Packet, index, cnt=1, size=16):
        '''
        @see https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/mifare/mifarehost.c#L866
        '''
        if not isinstance(data, Packet):
            raise ValueError('data should be Packet')
        if len(data) != cnt * size:
            raise ValueError('invalid len(data)')
        packet = Packet(len(data) + 3)
        packet[0: 3] = Packet([index, cnt, size])
        packet[3:] = data
        self.adapter.reset_input_buffer()
        self.adapter.sendCommandNG(PM3CMD['HF_MIFARE_EML_MEMSET'], packet)

    def mf_eget(self, index):
        self.adapter.reset_input_buffer()
        self.adapter.sendCommandNG(
            PM3CMD['HF_MIFARE_EML_MEMGET'], Packet([index, 1]))
        resp = self.adapter.waitRespTimeout(PM3CMD['HF_MIFARE_EML_MEMGET'])
        if resp.status:
            raise RuntimeError('Failed to read block from eml')
        return resp.data

    def mf_sim(
            self,
            type,
            uid: Packet = None,
            atqa: Packet = None,
            sak: Packet = None,
            exitAfter=0,
            interactive=False,
            nrArAttack=False,
            emukeys=False,
            cve=False):
        '''
        @see https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/cmdhfmf.c#L3416
        '''
        packet = Packet(16)
        flags = 0

        if uid:
            if not isinstance(uid, Packet):
                raise ValueError('uid should be Packet')
            if not len(uid) in [4, 7, 10]:
                raise ValueError('invalid len(uid)')
            packet[3: len(uid) + 3] = uid
            # FLAG_4B_UID_IN_DATA, FLAG_7B_UID_IN_DATA, FLAG_10B_UID_IN_DATA
            flags |= 1 << (len(uid) // 3)
        else:
            flags |= 0x10  # FLAG_UID_IN_EMUL

        if atqa:
            if not isinstance(atqa, Packet):
                raise ValueError('atqa should be Packet')
            if len(atqa) != 2:
                raise ValueError('invalid len(atqa)')
            packet[13:15] = atqa
            flags |= 0x800  # FLAG_FORCED_ATQA

        if sak:
            if not isinstance(sak, Packet):
                raise ValueError('sak should be Packet')
            if len(sak) != 1:
                raise ValueError('invalid len(sak)')
            packet[15:16] = sak
            flags |= 0x1000  # FLAG_FORCED_SAK

        if interactive:
            flags |= 0x1  # FLAG_INTERACTIVE
        if nrArAttack:
            flags |= 0x20  # FLAG_NR_AR_ATTACK
        if cve:
            flags |= 0x2000  # FLAG_CVE21_0430

        FLAGS_TYPE = {
            'mini': 0x80,
            '1k': 0x100,
            '2k': 0x200,
            '4k': 0x400,
        }
        type = type.lower()
        if type not in FLAGS_TYPE:
            raise ValueError('invalid type')
        flags |= FLAGS_TYPE[type]

        packet.set_uint16(0, flags)
        packet.set_uint8(2, exitAfter)

        self.adapter.reset_input_buffer()
        self.adapter.sendCommandNG(PM3CMD['HF_MIFARE_SIMULATE'], packet)
        if not interactive:
            return
        while True:
            resp = self.adapter.waitRespTimeout(PM3CMD['ACK'])
            if not nrArAttack:
                break
            if (resp.getArg(0) & 0xffff) != PM3CMD['HF_MIFARE_SIMULATE']:
                break
                # TODO: readerAttack not implemented
