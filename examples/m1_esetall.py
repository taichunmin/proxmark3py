import re
import proxmark3


if __name__ == "__main__":
    adapter = proxmark3.Proxmark3Adapter('/dev/cu.usbmodemiceman1')
    pm3 = proxmark3.Proxmark3(adapter)
    eml = '''F5C800635E880400C835002000000014
    06040001070208030904000000000000
    00000000000000000000000000000000
    ------------08778F69DFDACC6C36BF
    020100060080E1B047805F6C6801064F
    01F4011027102700E85A01320008007D
    92FD1656120000000000006400000059
    ------------08778F69E2F7BC1130BC
    F41000000BEFFFFFF410000000FF00FF
    F41000000BEFFFFFF410000000FF00FF
    53FDF37862300001F4102F016C70FF00
    ------------08778F698543577D7ED8
    630F0401009B5400000000000C179FEF
    6296AE7A62200000F4102C0103306000
    63D1AE7A62200000F410CF0103306000
    ------------08778F69559BA1C7EF5B
    5F65AD7A62200000F410600103306000
    60AEAD7A62200000F410600103306000
    6166AE7A62200000F410600103306000
    ------------08778F696434DCA18C34
    6296AE7A62200000F410600103306000
    63D1AE7A62200000F410600103306000
    5E952B7962200000F410600103306000
    ------------08778F693F387688DA11
    000A0002220000000000000000C41EF0
    00040022220000000000000000C61EDC
    620F0301009B540000000000020C9FEF
    ------------08778F6990FFC18E71D9
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F69D78D7AA8AF77
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F695B97F2542AB5
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F69EEF62C0A2EBF
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F695FF9EA1BED7B
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F6989B890C0128A
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F693ED25704B41F
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F690415EFE9EB4D
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F69DF78CC1D19B8
    00805F6C680000000000003264000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    ------------08778F6914CFCBAFCD05
    '''
    eml = re.sub(r'[^0-9A-Fa-f]', '', re.sub(r'-', '0', eml))
    eml = proxmark3.Packet.fromhex(eml)
    for i in range(64):
        pm3.mf_eset(eml.subarray((i << 4), (i << 4) + 16), i)
    pm3.mf_sim('1k')
