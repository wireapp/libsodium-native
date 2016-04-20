let g:syntastic_mode_map = {
			\ "mode": "active",
			\ "active_filetypes": [],
			\ "passive_filetypes": []}

let g:syntastic_cpp_checkers = ['gcc']
let g:syntastic_cpp_compiler = 'clang'
let g:syntastic_cpp_compiler_options = "-std=gnu++0x"
let g:syntastic_cpp_check_header = 0
let g:syntastic_cpp_include_dirs = [
			\ "/usr/include/node",
			\ "./node_modules/nan"]

set path+=/usr/include/node,./node_modules/nan
