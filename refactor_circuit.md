Matteo's suggestion of restructuring the `Circuit` trait.

1. Without the need to retain the private or public input values:
```rust
fn op<F>(f: F, a: u32, b: u32) -> u32 where F: Fn(u32, u32) -> u32 {
    f(a, b)
}

fn add(a: u32, b: u32) -> u32 {
    a + b
}

fn mul(a: u32, b: u32) -> u32 {
    a * b
}
```

2. With the option of retaining the private and public input values:
```rust
struct Foo<F>  where F: Fn(u32, u32) -> u32 {
    a: u32,
    b: u32,
    callback: F
}

impl<F> Foo<F> where F: Fn(u32, u32) -> u32 {
    fn calc(&self) -> u32 {
        (self.callback)(self.a, self.b)
    }
}

fn main() {

    let foo = Foo {
        a: 10,
        b: 20,
        callback: add,
    };

    println!("add: {}", op(add, 10, 20));
    println!("mul: {}", op(mul, 10, 20));

    println!("foo add: {}", foo.calc());
}
```

Notes:
- The funcitons `add` and `mul` would be different circuit implementation, returning the size of the circuit.
- I wouldn't know how to search for the circuit implementation in the AST though.

3. Another approach is the restructuring of the `Circuit` trait as proposed by Ed
