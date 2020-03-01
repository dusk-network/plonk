# Composer

WIP 

Every composer will have access to the Permutation, Linear combinations, linearisation poly, opening poly and quotient poly module.

It will be the responsibility of the Composer to build each polynomial


# Gotchas

 _How do I use the same composer but a different commitment scheme?_

 Currently this library only supports Commitment schemes that are homomorphic in property (see lineariser)

At the time of writing, you cannot switch out the commitment scheme even if it is homomorphic. This is because the Commitment Scheme module is still under construction. Once completed, switching commitment schemes will be simple as the composer will be made over a Commitment scheme trait.

It is still under consideration as to whether we will only ever allow homomorphic commitment schemes or have an (unrolled plonk) which supports all commitment schemes at the cost of larger proof sizes.

_How do I implement custom gates?_

Currently, implementing custom gates will take a bit of work on the developer side. We leave the Standard composer as an example on how to do this.
When implementing custom gates, this library allows you to reuse the following compoenents without duplication: Quotient poly (grand product component), Lineariser Poly (grand product component), Commitment scheme

The user is left to implement the circuit satisfiability equations for their custom gates in both the linearisation poly and the quotient poly.

There are plans to allow for elegant embedding of other composers. This may be possible currently, however it has not been formalised.

