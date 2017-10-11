class ltracebylineno(gdb.Command):
    """This command prints out the trace which nearby the input filename and line number
Usage: ltracebylineno [filename] [lineno]"""

    def __init__ (self):
        super (ltracebylineno, self).__init__("ltracebylineno", gdb.COMMAND_USER)
        self.traceDict = {}
        self.freetrace = None

    def inTraceNum(self, lines, lineno, i):
        if i == len(lines) - 1 and lines[i]["lineno"] <= lineno:
            return True
        if lines[i]["lineno"] <= lineno < lines[i+1]["lineno"]:
            return True
        return False

    def getTraceNum(self, lines, lineno):
        l, r = 0, len(lines)-1
        if not lines:
            return -1
        if lineno < lines[0]["lineno"]:
            return -1
        while l < r:
            mid = (l + r) / 2
            if self.inTraceNum(lines, lineno, mid):
                return mid
            if lineno < lines[mid]["lineno"]:
                r = mid - 1
            else:
                l = mid + 1
        if self.inTraceNum(lines, lineno, l):
            return l
        else:
            return r

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 2 and len(argv) != 0:
            raise gdb.GdbError("usage: ltracebylineno [filename] [lineno]")

        L = get_global_L()
        g = G(L)
        J = G2J(g)
        freetrace = trace_findfree(J)
        if not freetrace:
            raise gdb.GdbError("No trace found")

        if not self.traceDict or freetrace != self.freetrace:
            self.traceDict = {}
            for traceno in range(1, freetrace):
                T = traceref(J, traceno)
                pt = gcref(T['startpt'])['pt'].address
                pc = proto_bcpos(pt, mref(T['startpc'], "BCIns"))
                line = lj_debug_line(pt, pc)
                name = proto_chunkname(pt)
                path = lstr2str(name)
                filename = path[1:].split("/")[-1]
                if not self.traceDict.has_key(filename):
                    self.traceDict[filename] = {}
                if not self.traceDict[filename].has_key(path):
                    self.traceDict[filename][path] = []
                self.traceDict[filename][path].append({"lineno": int(line), "traceno": traceno})

        if len(argv) == 0:
            #out("ltracebylineno.traceDict = %s\n" % str(self.traceDict))
            raise gdb.GdbError("usage: ltracebylineno [filename] [lineno]")
            return

        filename = argv[0]
        lineno = int(argv[1])

        if not self.traceDict.has_key(filename):
            out("Don't have this file.\n")
            return

        for path, lines in self.traceDict[filename].items():
            i = self.getTraceNum(lines, lineno)
            if i == -1:
                traceno = 0
            else:
                traceno = lines[i]["traceno"]
                line = lines[i]["lineno"]
            out("trace %d\n" % traceno)
            if 0 < traceno < freetrace:
                T = traceref(J, traceno)
                start = T['mcode']
                szmcode = int(T['szmcode'])
                out("machine code size: %d\n" % szmcode)
                out("machine code start addr: 0x%x\n" % ptr2int(T['mcode']))
                out("machine code end addr: 0x%x\n" % (ptr2int(T['mcode']) + szmcode))
                out("%s:%d\n" % (path, line))

ltracebylineno()

def debug_varname_for_lwhere2(pt, pc, slot, target_name):
    print target_name
    p = proto_varinfo(pt).cast(typ("char*"))
    if p:
        lastpc = 0
        while True:
            name = p
            vn = p.cast(typ("uint8_t*")).dereference().cast(typ("uint32_t"))
            if vn < VARNAME__MAX:
                if vn == VARNAME_END:
                    break
            else:
                while True:
                    p += 1
                    if p.cast(typ("uint8_t*")).dereference() == 0:
                        break
            p += 1
            v, p = lj_buf_ruleb128(p)
            startpc = lastpc + v
            lastpc = startpc
            if startpc > pc:
                break
            v, p = lj_buf_ruleb128(p)
            endpc = startpc + v
            if pc < endpc and slot == 0:
                if vn < VARNAME__MAX:
                    this_name = builtin_variable_names[int(vn - 1)]
                    if this_name == target_name:
                        out("\tlocal \"%s\"\n" % this_name)
                else:
                    #out("\tlocal \"%s\":\n" % name.string('iso-8859-6', 'ignore'))
                    pass
                return True
            slot = slot - 1
    return False

def lj_debug_dumpstack_for_lwhere2(L, T, depth, base, full, target_name):
    print target_name
    global cfunc_cache

    level = 0
    dir = 1
    if depth < 0:
        level = ~depth
        depth = dir = -1

    bot = tvref(L['stack'])
    while level != depth:
        #print "checking level: %d" % level

        bt = ""
        frame, size = lj_debug_frame(L, base, level, bot)

        if frame:
            nextframe = (frame + size) if size else null()
            fn = frame_func(frame)
            #print "type(fn) == %s" % fn.type
            if not fn:
                return

            pt = None

            if isluafunc(fn):
                pt = funcproto(fn)
                line = debug_frameline(L, T, fn, pt, nextframe)
                #print("line: %d\n" % line)
                if line <= 0:
                    #print str(pt.dereference)
                    line = int(pt['firstline'])
                name = proto_chunkname(pt)
                if not name:
                    return ""
                path = lstr2str(name)
                bt += "%s:%d\n" % (path, line)

            elif isffunc(fn):
                bt += "builtin#%d\n" % int(fn['c']['ffid'])

            else:
                cfunc = fn['c']['f']
                key = str(cfunc)
                if key in cfunc_cache:
                    sym = cfunc_cache[key]

                else:
                    sym = "C:%s\n" % cfunc
                    m = re.search('<.*?(\w+)*.*?>', cfunc.__str__())
                    if m:
                        sym = "C:%s\n" % m.group(1)
                    else:
                        sym = "C:%s\n" % key

                    cfunc_cache[key] = sym

                bt += sym
                #print "bt: " + sym

            #out(bt)

            if full:
                if not pt:
                    pt = funcproto(fn)
                pc = debug_framepc(L, T, fn, pt, nextframe)
                if pc != NO_BCPOS:
                    nf = nextframe
                    if not nf:
                        nf = L['top']
                    for slot in xrange(1, int(nf - frame)):
                        tv = frame + slot
                        if debug_varname_for_lwhere2(pt, pc, slot - 1, target_name):
                            dump_tvalue(tv)

        elif dir == 1:
            break

        else:
            level -= size

        level += dir

    return bt

class lwhere2(gdb.Command):
    """This command can print some variable value by name"""

    def __init__ (self):
        super (lwhere2, self).__init__("lwhere2", gdb.COMMAND_USER)

    def getTableValue (self, table, key):
        m = re.match('0x[0-9a-fA-F]+', table)
        if m:
            val = gdb.Value(int(table, 16)).cast(typ("TValue*"))
        else:
            val = gdb.parse_and_eval(table)

        if not val:
            raise gdb.GdbError("table argument empty")
            return

        typstr = str(val.type)
        if typstr == "GCtab *":
            tab = val
        else:
            tab = tabV(val)

        tv = lj_tab_getstr(tab, key)
        if tv:
            out("(TValue*)%#x\n" % ptr2int(tv))
            dump_tvalue(tv)
        else:
            raise gdb.GdbError("Key \"%s\" not found." % key)

    def getG (self, name):
        L = get_cur_L()
        _G = "(GCtab*)0x%x\n" % ptr2int(tabref(L['env']))
        self.getTableValue(_G, name)

    def getR (self, name):
        L = get_cur_L()
        g = G(L)
        registry = "(TValue*)0x%x\n" % ptr2int(g['registrytv'].address)
        self.getTableValue(registry, name)

    def getL (self, name):
        L = get_cur_L()
        g = G(L)
        full = True

        vmstate = int(g['vmstate'])
        #print "vmstate = %d" % vmstate

        if vmstate >= 0:
            #print "compiled code"
            traceno = vmstate
            J = G2J(g)
            T = traceref(J, traceno)
            base = tvref(g['jit_base'])
            if not base:
                try:
                    base = tvref(g['saved_jit_base'])
                except:
                    pass

            if not base:
                raise gdb.GdbError("jit base is NULL (trace #%d)" % int(T['traceno']))
            bt = lj_debug_dumpstack(L, T, 30, base, full)

        else:
            if vmstate == ~LJ_VMST_EXIT:
                base = tvref(g['jit_base'])
                if base:
                    bt = lj_debug_dumpstack(L, 0, 30, base, full)

                else:
                    base = L['base']
                    bt = lj_debug_dumpstack(L, 0, 30, base, full)

            else:
                if vmstate == ~LJ_VMST_INTERP and not L['cframe']:
                    out("No Lua code running.\n")
                    return

                if vmstate == ~LJ_VMST_INTERP or \
                       vmstate == ~LJ_VMST_C or \
                       vmstate == ~LJ_VMST_GC:
                    if vmstate == ~LJ_VMST_INTERP:
                        #out("Fetching edx...")
                        base = gdb.parse_and_eval("$edx").cast(typ("TValue*"))

                    else:
                        base = L['base']

                    bt = lj_debug_dumpstack(L, 0, 30, base, full)

                else:
                    out("No Lua code running.\n")
                    return

    def invoke (self, args, from_tty):
        argv = gdb.string_to_argv(args)

        if len(argv) != 2:
            raise gdb.GdbError("usage: lwhere2 G/R/L name")
        
        ran = argv[0]
        name = argv[1]
        
#        L = get_cur_L()
#        Ls = L.dereference()
#        for k in Ls.type.keys():
#            print k, ": ", Ls[k]
#        g = G(L)
#        gs = g.dereference()
#        for k in gs.type.keys():
#            print k, ": ", gs[k]

        if ran == 'G':
            self.getG(name)
        elif ran == 'R':
            self.getR(name)
        elif ran == 'L':
            self.getL(name)
        else:
            raise gdb.GdbError("usage: lwhere2 G/R/L name")

lwhere2()

