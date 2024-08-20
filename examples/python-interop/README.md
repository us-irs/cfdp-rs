Python Interoperability Example for cfdp-rs
=======

This example application showcases the interoperability of the CFDP handlers written in Rust
with a Python implementation which uses [cfdp-py](https://github.com/us-irs/cfdp-py) library.

Both the Rust and the Python app exchange packet data units via a UDP interface and launch
both a destination and source handler. As such, they are both able to send and receive files.
Both applications can be started with the command line argument `-f` to initiate a file transfer.
You can run both applications with `-h` to get more information about the available options.

## Running the Python App

It is recommended to run the Python App in a dedicated virtual environment. For example, on a
Unix system you can use `python3 -m venv venv` and then `source venv/bin/activate` to create
and activate a virtual environment.

After that, you can install the required dependencies using

```sh
pip install -r requirements.txt
```

and then run the application using `./main.py` or `python3 main.py`.

It is recommended to run `./main.py -h` first to get an overview of some possible options.
Running the Python App with `./main.py -f` will cause the Python App to start a file copy operation
with fixed temporary paths.

## Running the Rust App

You can run the Rust application using `cargo`, for example `cargo run --example python-interop`.
It is recommended to run `cargo run --example python-interop -- -h` to get an overview of some
possible launch options.

Running the Rust App with `cargo run --example python-interop -- -f` will cause the Rust app to
start a file copy operation with fixed temporary paths.
