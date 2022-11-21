# psp2mmap

<h1>WIP</h1>

Currently only the following are supported

- PROT_READ
- PROT_WRITE
- PROT_NONE
- MAP_SHARED



Currently only 3.60 is supported. For other fw support you need to add new offset to function `prog_start`.

## Known issue

intr problem
```
`mmap_excp_handler` does enable interrupts for sceIoPread/sceIoPwrite, but the behavior is undefined if process_exit intr occurs at that moment.
So developers should program in a way that takes that into account.
However, the probability of encountering this problem is less than 3%.
```


Also see issue tab
