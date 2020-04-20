In this module, the notes on how the prover 
algorithm and verification functions are constructed
for PLONK, are documented.

PLONK proof construction 
========================

Following on from the generic
SNARK construction, given in
[Proof construction components](snark_construction/index.html), 
here we will give the set up
of a PLONK proof and show 
which steps need to be satisfied
as part of the protocol.

First we will explain the 
derivation and simplification 
of the arithmetic circuits. 

PLONK uses both gate constraints 
and copy constraints, to collect 
like expressions. Using the same
example of:

\\[
\mathbf{W}\_*L* \cdot \mathbf{W}\_*R* = \mathbf{W}\_*O*,
\\]

We can express multiples of the 
same wires in or out of the same 
gate, with the above equation.
PLONK also uses 'copy
constraints', which are used to 
associate wires, which have 
equality, from the entire circuit.

Thus we have 'ith' gates, so the 
index from left or right across 
the circuit is mitigated for 
wires which are equal. 

For example, in the two equations:

\\[
\begin{aligned}
\mathbf{A}\_*1* \circ X \cdot \mathbf{B}\_*1* \circ \X^{2} 
= \mathbf{C}\_*1*\\\\
and 
\mathbf{A}\_*2* \circ X^{2} \cdot \mathbf{B}\_*2* \circ \X 
= \mathbf{C}\_*2*\\\\
\end{aligned}
\\]

We can state the equalities that: 
\\[
\begin{aligned} 
\mathbf{A}\_*1* = \mathbf{B}\_*2* \\\\
&\\\\
\mathbf{B}\_*1* = \mathbf{A}\_*2* \\\\
\end{aligned}
\\]

These are examples of constraints 
collected in PLONK. Which is done
the same for addition gates, except
the gate constrain satisfies:

\\[
\mathbf{W}\_*L* + \mathbf{W}\_*R* = \mathbf{W}\_*O*,
\\]

After the constriants
are made, they are formatted into a 
system of mumerical equations, 
which in PLONK are reduced to a 
small amount of polynomial 
equations which are capable of 
representing the two types.
PLONK allows us to combine the
two gate equations by describing 
their relationship relative to 
the role in the circuit.
PLONK also has constant, which
are denoted as 'Q'. These 
values will change for each 
programme. When they are 
combined with the gate 
equations, we get the 
polynomial equation for 
a reduced form as:

\\[
\begin{aligned}  
*L* = left \\\\
*R* = right \\\\
*O* = output \\\\
*M* = multiplication \\\\ 
*C* = constants \\\\

\mathbf{Q}\_*L\_i* \circ a\_i +
\mathbf{Q}\_*R\_i* \circ b\_i +
\mathbf{Q}\_*0\_i* \circ c\_i +
\mathbf{Q}\_*M\_i* \circ a\_ib\_i +
\mathbf{Q}\_*C\_i* =
0
\end{aligned}
\\]
This can be used for both
addition and multiplication
gates, where there values 
can be provided by the user 
depending on the circuit 
composition. 
For an addition gate, 
we derive it as follows:

\\[
\begin{aligned}
\mathbf{Q}\_*L\_i* = 1
\mathbf{Q}\_*R\_i* = 1
\mathbf{Q}\_*0\_i* = -1
\mathbf{Q}\_*M\_i* = 0
\mathbf{Q}\_*C\_i* = 1
\end{aligned}
\\]

Which results in:
\\[
\begin{aligned}  
a\_i +
b\_i -
c\_i =
0
\end{aligned}
\\]




