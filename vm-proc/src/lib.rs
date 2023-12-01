use proc_macro::TokenStream;

use syn::{Block, ItemFn};

#[proc_macro_attribute]
pub fn handler(_attr: TokenStream, fn_ts: TokenStream) -> TokenStream {
    #[allow(unused_mut)]
    let ItemFn {
        attrs,
        vis,
        mut sig,
        block,
    } = syn::parse(fn_ts).expect("failed to parse as fn");

    let function_data = ItemFn {
        attrs,
        vis,
        sig: sig.clone(),
        block,
    };

    #[cfg(feature = "enabled")]
    {
        use syn::Ident;
        sig.ident = Ident::new(
            &format!("{}_handler", sig.ident.to_string().replace("r#", "")),
            sig.ident.span(),
        );

        let first_arg = sig.inputs[0].clone();
        sig.inputs.clear();
        sig.inputs.push(first_arg);
    }

    let handler_block: Box<Block> = {
        syn::parse(
            ({
                #[cfg(feature = "enabled")]
                {
                    let ident = function_data.sig.ident.clone();

                    quote::quote! {{
                    unsafe {
                    let _vm = vm;
                    core::arch::asm!(
                        "push rsi",
                        "mov rsi, rcx",
                        "mov rax, qword ptr [rcx]",
                        "movzx rdx, byte ptr [rax]",
                        "inc rax",
                        "mov qword ptr [rcx], rax",
                        "call {}", // todo manually inline here maybe
                        "mov rax, qword ptr [rsi]",
                        "mov rcx, qword ptr [rax]",
                        "add rax, 8",
                        "mov qword ptr [rsi], rax",
                        "mov rax, rcx",
                        "mov rcx, rsi",
                        "pop rsi",
                        "push rcx",
                        "mov rcx, qword ptr gs:[0x60]",
                        "mov rcx, [rcx + 0x10]",
                        "add rax, rcx",
                        "pop rcx",
                        "jmp rax",
                        ".fill 80, 1, 0xcc", // padding to allow for obfuscation in place
                        sym #ident,
                        options(nostack, noreturn)
                    )}
                    }}
                }

                #[cfg(not(feature = "enabled"))]
                {
                    let block = function_data.block;
                    quote::quote! { #block }
                }
            })
                .into(),
        )
            .unwrap()
    };

    #[cfg(feature = "enabled")]
    {
        (quote::quote! {
            // #[inline(always)]
            #function_data

            // not sure wether to inline this or not
            #[inline(never)]
            #[doc(hidden)]
            #[no_mangle]
            pub #sig -> ! {
                #handler_block
            }
        })
            .into()
    }
    #[cfg(not(feature = "enabled"))]
    {
        (quote::quote! {
            pub #sig {
                #handler_block
            }
        })
            .into()
    }
}
