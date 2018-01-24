# NVStore

A lightweight module providing the functionality of storing data by keys in the internal flash, for security purpose.

## Description

NVStore provides the ability to store a minimal set of system critical items in the internal flash.
For each item key, NVStore module provides the ability to set the item data or get it.
Newly set values are added to the flash (as in journal), with the effect of overriding the previous value for this key.
NVStore module ensures that existing data isn't harmed by power failures, during any operation.
The full interface can be found under nvstore.h.

### Flash structure
NVStore uses two Flash areas, active and non-active. Data is written to the active area, until it gets full.
When it does, garbage collection is invoked, compacting items from the active area to the non-active one,
and switching activity between areas.
Each item is kept in an entry, containing header and data, where the header holds the item key, size and CRC.
Each area must consist of one or more erasable units (sectors). 

### APIs
- init: Initialize NVStore (also lazily called by get, set, set_once and remove APIs).
- deinit: Deinitialize NVStore.
- get: Get the value of an item, given key. 
- set: Set the value of an item, given key and value. 
- set_once: Like set, but allows only a one time setting of this item (and disables deleting of this item).
- remove: Remove an item, given key.
- get_item_size: Get the item value size (in bytes).
- set_max_keys: Set maximal value of unique keys. Overriding the default of NVSTORE_MAX_KEYS. This affects RAM consumption,
  as NVStore consumes 4 bytes per unique key. Reinitializes the module.


## Usage

### Configuring NVStore for your board
NVStore requires the addresses and sizes of both areas in flash. For this purpose, the following values should be defined in 
mbed_lib.json, for each supported board:
- area_1_address
- area_1_size 
- area_2_address
- area_2_size 

In addition, the num_keys value should be modified, in order to change the default number of different keys.  

### Using NVStore
NVStore is a singleton class, meaning that the system can have only a single instance of it.
To instanciate NVStore, one needs to call its get_instance member function as following:
``` c++
    NVStore &nvstore = NVStore::get_instance();
```
After the NVStore instantiation, one can call the init API, but it is not necessary, as all
NVStore APIs (get, set et al.) perform a "lazy initialization".

### Testing NVStore
Run the NVStore functionality test with the mbed command as following:
mbed test -n features-nvstore-tests-nvstore-functionality