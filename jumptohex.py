############################################################################################
##
## IDA Jump to Hex View!
##
## Available for IDA 7+ and Python 3.8+
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##
## To run:
##      Right-click on an address in the disassembly and select "Jump to Hex View"
##
############################################################################################

__AUTHOR__ = "@sean2077"

PLUGIN_NAME = "Jump to Hex View"
PLUGIN_HOTKEY = "Ctrl+Shift+J"
VERSION = "1.0.0"

ACTION_PREFIX = "sean2077"

import ida_kernwin
import idaapi
import idc


def jump_to_hex_action():
    ea = idc.get_screen_ea()
    if ea == idaapi.BADADDR:
        idaapi.warning("Invalid address selected")
        return

    idaapi.msg(f"Jumping to Hex View at address: {ea:#x}")

    # Check if Hex View is open
    hex_view = idaapi.find_widget("Hex View-1")
    if hex_view is None:
        idaapi.refresh_idaview_anyway()
        ida_kernwin.process_ui_action("ToggleDump")
        hex_view = idaapi.find_widget("Hex View-1")

    if hex_view:
        ida_kernwin.activate_widget(hex_view, True)
        ida_kernwin.jumpto(ea)
    else:
        idaapi.warning("Failed to open Hex view, please open it manually from the View menu.")


class JumpToHex(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Jump to Hex View"
    help = "Right-click an address and select 'Jump to Hex'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self._init_action_jump_to_hex()
        self._init_hooks()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        self._hooks.unhook()
        self._del_action_jump_to_hex()
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.hook()

    ACTION_JUMP_TO_HEX = f"{ACTION_PREFIX}:jump_to_hex"

    def _init_action_jump_to_hex(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_JUMP_TO_HEX,
            "Jump to Hex",
            IDACtxEntry(jump_to_hex_action),
            PLUGIN_HOTKEY,
            "Jump to hex view at the current address",
            0,
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_jump_to_hex(self):
        idaapi.unregister_action(self.ACTION_JUMP_TO_HEX)


class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        inject_jump_to_hex_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0


def inject_jump_to_hex_actions(form, popup, form_type):
    if form_type == idaapi.BWN_DISASM:
        idaapi.attach_action_to_popup(form, popup, JumpToHex.ACTION_JUMP_TO_HEX, "Jump to Hex", idaapi.SETMENU_APP)
    return 0


class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY():
    return JumpToHex()
