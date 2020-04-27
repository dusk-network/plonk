# Examples folder

These examples are intended to explain to the user how the library can be used and
also all of the options that it provides, as well as the addressing some common questions
that the end-user may have.

## Running the examples
To run the examples, run:
> cargo run --example $example_name.rs

## Table of contents

Examples are split into 5 files at the moment (which may be extended in the future).


1. `0_setup_srs` tries to show to the user how to generate a "Trusted Setup"
in order to test the circuit proving/verifying implementations that they
execute for  their projects. 
**The 'Trusted Setups' generated with PLONK should NEVER be used in production.
They only try to provide a way to the users to test their implementations (which
will need a 'Trusted Setup')**

2. `1_compose_prove_verify` is basically a detailing of the variety of capabilities
the library has, which will show all the steops , from the beginning to end, of 
how to build & compile circuits. This file includes the steps for as generating 
`Proof`s with the circuit and how to verify them.
It includes a bunch of documentation that explains all of these processes, step by step,
as well as why its done.

3. `2_gadget_orientation` tries to introduce to the user to the gadget orientation
for using PLONK. Basically, this is the our reccomended methodology that leads to cleaner
code, including fewer duplications and more performance. It tries to not include
extra crates and explains step by step everything that is needed for the dependecies. 
There are also some coments on what could be improved to give a better implementation.

4. `3_0_setup_for_gadgets` shows how to setup all of the parameters that you can
pre-compute, as seen in example `2_gadget_orientation`, as an easy & quick way whcih is 
then used for our final reccomendation of how to implement PLONK in your
library stack.

5. `3_1_final_gadget_orientation` is basically the **model file** of how the final code
of your PLONK implementations should look like to allow better readability and avoid 
code duplications and/or errors in the implementation.
All of the things that we do there are explained on the previous examples. So if you feel
lost while looking at it, you can refer directly to the the previous example
files.


## Suggestions and/or improvements
- Feel free to open an issue regarding anything that is not clear enough or if there is anything
could be explained better!
- PR's with your suggestions or improvements of these examples are welcome!