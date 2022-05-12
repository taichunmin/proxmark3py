import proxmark3

if __name__ == "__main__":
    adapter = proxmark3.Proxmark3Adapter('/dev/cu.usbmodemiceman1')
    pm3 = proxmark3.Proxmark3(adapter)
    for i in range(64):
        print(pm3.mf_eget(i))
