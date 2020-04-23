# Examples folder

These examples pretend to explain to the user how the library can be used and
also all of the options that it provides as well as the more common questions
that the end-user may have.

## Running the examples
To run the examples, run:
> cargo run --example $example_name.rs

## Table of contents

Examples are splited into 5 files at the moment (we might extend it on the future).


1. `0_setup_srs` tries to show to the user how to generate a "Trusted Setup"
in order to test the circuit proving/verifying implementations that they
implement on their projects. 
**The "Tusted Setups" generated with PLONK SHOULD NEVER be used in production.
They only try to provide a way to the users to test their implementations (which
will need a "Trusted Setup")**

2. `1_compose_prove_verify` is basically a travel over the whole capabilities of 
the library, which will show from the beggining to the end how to build & compile
circuits as well as generating `Proof`s with them and verify those ones.
It includes a bunch of documentation that explains step by step everything that is 
done and why is done.

3. `2_gadget_orientation` tries to introduce to the user to the gadget orientation
of plonk usage. Basically this is the way on which we think that leads to cleaner
code as well as less code duplications and more performance. It tries to not include
extra crates and explains step by step everything that is done there. 
It also adds some coments on what could be improved to lead to a better implementation.

4. `3_0_setup_for_gadgets` shows how to setup all of the parameters that you can
pre-compute as seen in example `2_gadget_orientation` on an easy & quick way and that
will then be used for our final and recommended way of implementing plonk in your
library stack.

5. `3_1_final_gadget_orientation` is basically the **model file** or how the final code
on your plonk implementations should look like to allow better readability and avoid 
code duplications and/or errors in the implementation.
All of the things that we do there are explained on the previous examples. So if you feel
lost while looking at it, you should definitely take a look to the previous example
files.


## Suggestions and/or improvements
- Feel free to open an issue regarding anything that it's not clear enough or that
could be explained better!
- PR's with your suggestions or improvements of these examples are welcome!