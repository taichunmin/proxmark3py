# proxmark3py

A proxmark3 library base on [pyserial](https://pyserial.readthedocs.io/en/latest/pyserial.html)

## install

```
python3 -m pip install proxmark3py
```

## Usage

* list available ports

```bash
python -m serial.tools.list_ports
```

* Initialize `proxmark3`

```python
import proxmark3
adapter = proxmark3.Proxmark3Adapter('/dev/cu.usbmodemiceman1') # change to your proxmark3 serial port
pm3 = proxmark3.Proxmark3(adapter)
```
