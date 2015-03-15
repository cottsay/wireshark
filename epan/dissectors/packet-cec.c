/* packet-cec.c
 * Routines for HDMI CEC dissection
 * By Scott K logan <logans@cottsay.net
 * Copyright 2014 Scott K Logan
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>

static int proto_cec = -1;
static gint ett_cec = -1;
static gint ett_cec_params = -1;
static gint ett_cec_audio_status = -1;
expert_module_t *expert_cec = NULL;
static dissector_handle_t cec_handle;

static int hf_cec_abort_reason = -1;
static const value_string cec_abort_reason[] = {
	{ 0x00, "Unrecognized Opcode" },
	{ 0x01, "Not in correct mode to respond" },
	{ 0x02, "Cannot provide source" },
	{ 0x03, "Invalid operand" },
	{ 0x04, "Refused" },
};

static int hf_cec_analogue_broadcast_type = -1;
static const value_string cec_analogue_broadcast_type[] = {
	{ 0x00, "Cable" },
	{ 0x01, "Satellite" },
	{ 0x02, "Terrestrial" },
};

static int hf_cec_analogue_frequency = -1;
void cec_fmt_analogue_frequency(gchar *s, guint32 v)
{
	float hz = 62.5f * (v & 0xFFFF);
	g_snprintf(s, ITEM_LABEL_LENGTH, "%f kHz", hz);
}

static int hf_cec_audio_mute_status = -1;
static const value_string cec_audio_mute_status[] = {
	{ 0x00, "Un-Muted" },
	{ 0x01, "Muted" },
};

static int hf_cec_audio_rate = -1;
static const value_string cec_audio_rate[] = {
	{ 0x00, "Rate Control Off" },
	{ 0x01, "Standard Rate: 100%" },
	{ 0x02, "Fast Rate: 101% Max" },
	{ 0x03, "Slow Rate: 99% Min" },
	{ 0x04, "Standard Rate: 100.0%" },
	{ 0x05, "Fast Rate: 100.1% Max" },
	{ 0x06, "Slow Rate: 99.9% Min" },
};

static int hf_cec_audio_status = -1;

static int hf_cec_audio_volume_status = -1;
void cec_fmt_audio_volume_status(gchar *s, guint32 v)
{
	guint8 pct = v & 0x7F;
	if (pct <= 100) {
		g_snprintf(s, ITEM_LABEL_LENGTH, "%u%%", pct);
	} else if (v == 0x7F) {
		g_snprintf(s, ITEM_LABEL_LENGTH, "(Unknown)");
	} else {
		g_snprintf(s, ITEM_LABEL_LENGTH, "(Reserved)");
	}
}

static int hf_cec_broadcast_system = -1;
static const value_string cec_broadcast_system[] = {
	{ 0x00, "PAL B/G" },
	{ 0x01, "SECAM L'" },
	{ 0x02, "PAL M" },
	{ 0x03, "NTSC M" },
	{ 0x04, "PAL I" },
	{ 0x05, "SECAM DK" },
	{ 0x06, "SECAM B/G" },
	{ 0x07, "SECAM L" },
	{ 0x08, "PAL DK" },
	{ 0x1F, "Other System" },
};

static int hf_cec_cdc_message = -1;
static const value_string cec_cdc_message[] = {
	{ 0x00, "CDC_HEC_InquireState" },
	{ 0x01, "CDC_HEC_ReportState" },
	{ 0x02, "CDC_HEC_SetState" },
	{ 0x03, "CDC_HEC_RequestDeactivation" },
	{ 0x04, "CDC_HEC_NotifyAlive" },
	{ 0x05, "CDC_HEC_Discover" },
	{ 0x06, "CDC_HEC_SetStateAdjacent" },
};

static int hf_cec_deck_control_mode = -1;
static const value_string cec_deck_control_mode[] = {
	{ 0x01, "Skip Forward / Wind" },
	{ 0x02, "Skip Reverse / Rewind" },
	{ 0x03, "Stop" },
	{ 0x04, "Eject" },
};

static int hf_cec_deck_info = -1;
static const value_string cec_deck_info[] = {
	{ 0x11, "Play" },
	{ 0x12, "Record" },
	{ 0x13, "Play Reverse" },
	{ 0x14, "Still" },
	{ 0x15, "Slow" },
	{ 0x16, "Slow Reverse" },
	{ 0x17, "Fast Forward" },
	{ 0x18, "Fast Reverse" },
	{ 0x19, "No Media" },
	{ 0x1A, "Stop" },
	{ 0x1B, "Skip Forward / Wind" },
	{ 0x1C, "Skip Reverse / Rewind" },
	{ 0x1D, "Index Search Forward" },
	{ 0x1E, "Index Search Reverse" },
	{ 0x1F, "Other Status" },
};

static int hf_cec_device_type = -1;
static const value_string cec_device_type[] = {
	{ 0x00, "TV" },
	{ 0x01, "Recording Device" },
	{ 0x03, "Tuner" },
	{ 0x04, "Playback Device" },
	{ 0x05, "Audio System" },
};

static int hf_cec_destination = -1;
static const value_string cec_destination[16] = {
	{ 0x0, "TV" },
	{ 0x1, "Recording Device 1" },
	{ 0x2, "Recording Device 2" },
	{ 0x3, "Tuner 1" },
	{ 0x4, "Playback Device 1" },
	{ 0x5, "Audio System" },
	{ 0x6, "Tuner 2" },
	{ 0x7, "Tuner 3" },
	{ 0x8, "Playback Device 2" },
	{ 0x9, "Recording Device 3" },
	{ 0xA, "Tuner 4" },
	{ 0xB, "Playback Device 3" },
	{ 0xE, "Free Use" },
	{ 0xF, "Broadcast" },
};

static int hf_cec_initiator = -1;
static const value_string cec_initiator[16] = {
	{ 0x0, "TV" },
	{ 0x1, "Recording Device 1" },
	{ 0x2, "Recording Device 2" },
	{ 0x3, "Tuner 1" },
	{ 0x4, "Playback Device 1" },
	{ 0x5, "Audio System" },
	{ 0x6, "Tuner 2" },
	{ 0x7, "Tuner 3" },
	{ 0x8, "Playback Device 2" },
	{ 0x9, "Recording Device 3" },
	{ 0xA, "Tuner 4" },
	{ 0xB, "Playback Device 3" },
	{ 0xE, "Free Use" },
	{ 0xF, "Unregistered" },
};

static int hf_cec_menu_language = -1;

static int hf_cec_menu_request_type = -1;
static const value_string cec_menu_request_type[] = {
	{ 0x00, "Activate" },
	{ 0x01, "Deactivate" },
	{ 0x02, "Query" },
};

static int hf_cec_menu_state = -1;
static const value_string cec_menu_state[] = {
	{ 0x00, "Activated" },
	{ 0x01, "Deactivated" },
};

static int hf_cec_osd_name = -1;

static int hf_cec_opcode = -1;
static const value_string cec_opcode[] = {
	{ 0x00, "Feature Abort" },
	{ 0x04, "Image View On" },
	{ 0x05, "Tuner Step Increment" },
	{ 0x06, "Tuner Step Decrement" },
	{ 0x07, "Tuner Device Status" },
	{ 0x08, "Give Tuner Device Status" },
	{ 0x09, "Record On" },
	{ 0x0A, "Record Status" },
	{ 0x0B, "Record Off" },
	{ 0x0D, "Text View On" },
	{ 0x0F, "Record TV Screen" },
	{ 0x1A, "Give Deck Status" },
	{ 0x1B, "Deck Status" },
	{ 0x32, "Set Menu Language" },
	{ 0x33, "Clear Analogue Timer" },
	{ 0x34, "Set Analogue Timer" },
	{ 0x35, "Timer Status" },
	{ 0x36, "Standby" },
	{ 0x41, "Play" },
	{ 0x42, "Deck Control" },
	{ 0x43, "Timer Cleared Status" },
	{ 0x44, "User Control Pressed" },
	{ 0x45, "User Control Released" },
	{ 0x46, "Give OSD Name" },
	{ 0x47, "Set OSD Name" },
	{ 0x64, "Set OSD String" },
	{ 0x67, "Set Timer Program Title" },
	{ 0x70, "System Audio Mode Request" },
	{ 0x71, "Give Audio Status" },
	{ 0x72, "Set System Audio Mode" },
	{ 0x7A, "Report Audio Status" },
	{ 0x7D, "Give System Audio Mode Status" },
	{ 0x7E, "System Audio Mode Status" },
	{ 0x80, "Routing Change" },
	{ 0x81, "Routing Information" },
	{ 0x82, "Active Source" },
	{ 0x83, "Give Physical Address" },
	{ 0x84, "Report Physical Address" },
	{ 0x85, "Request Active Source" },
	{ 0x86, "Set Stream Path" },
	{ 0x87, "Device Vendor ID" },
	{ 0x89, "Vendor Command" },
	{ 0x8A, "Vendor Remote Button Down" },
	{ 0x8B, "Vendor Remote Button Up" },
	{ 0x8C, "Give Device Vendor ID" },
	{ 0x8D, "Menu Request" },
	{ 0x8E, "Menu Status" },
	{ 0x8F, "Give Device Power Status" },
	{ 0x90, "Report Power Status" },
	{ 0x91, "Get Menu Language" },
	{ 0x92, "Set Analogue Service" },
	{ 0x93, "Set Digital Service" },
	{ 0x97, "Set Digital Timer" },
	{ 0x99, "Clear Digital Timer" },
	{ 0x9A, "Set Audio Rate" },
	{ 0x9D, "Inactive Source" },
	{ 0x9E, "CEC Version" },
	{ 0x9F, "Get CEC Version" },
	{ 0xA0, "Vendor Command With ID" },
	{ 0xA1, "Clear External Timer" },
	{ 0xA2, "Set External Timer" },
	{ 0xC0, "Initiate ARC" },
	{ 0xC1, "Report ARC Initiated" },
	{ 0xC2, "Report ARC Terminated" },
	{ 0xC3, "Request ARC Initiation" },
	{ 0xC4, "Request ARC Termination" },
	{ 0xC5, "Terminate ARC" },
	{ 0xF8, "CDC Message" },
	{ 0xFF, "Abort" },
};

static int hf_cec_parameters = -1;

static int hf_cec_physical_address = -1;
void cec_fmt_physical_address(gchar *s, guint32 v)
{
	g_snprintf(s, ITEM_LABEL_LENGTH, "%hhX.%hhX.%hhX.%hhX",
		v >> 12 & 0xF,
		v >> 8 & 0xF,
		v >> 4 & 0xF,
		v & 0xF);
}

static int hf_cec_power_status = -1;
static const value_string cec_power_status[] = {
	{ 0x00, "On" },
	{ 0x01, "Standby" },
	{ 0x02, "In transition Standby to On" },
	{ 0x03, "In transition On to Standby" },
};

static int hf_cec_status_request = -1;
static const value_string cec_status_request[] = {
	{ 0x01, "On" },
	{ 0x02, "Off" },
	{ 0x03, "Once" },
};

static int hf_cec_system_audio_status = -1;
static const value_string cec_system_audio_status[] = {
	{ 0x00, "Off" },
	{ 0x01, "On" },
};

static int hf_cec_user_control_code = -1;
static const value_string cec_user_control_code[] = {
	{ 0x00, "Select" },
	{ 0x01, "Up" },
	{ 0x02, "Down" },
	{ 0x03, "Left" },
	{ 0x04, "Right" },
	{ 0x05, "Right-Up" },
	{ 0x06, "Right-Down" },
	{ 0x07, "Left-Up" },
	{ 0x08, "Left-Down" },
	{ 0x09, "Root Menu" },
	{ 0x0A, "Setup Menu" },
	{ 0x0B, "Contents Menu" },
	{ 0x0C, "Favorites Menu" },
	{ 0x0D, "Exit" },
	{ 0x20, "0" },
	{ 0x21, "1" },
	{ 0x22, "2" },
	{ 0x23, "3" },
	{ 0x24, "4" },
	{ 0x25, "5" },
	{ 0x26, "6" },
	{ 0x27, "7" },
	{ 0x28, "8" },
	{ 0x29, "9" },
	{ 0x2A, "Dot" },
	{ 0x2B, "Enter" },
	{ 0x2C, "Clear" },
	{ 0x2F, "Next Favorite" },
	{ 0x30, "Channel Up" },
	{ 0x31, "Channel Down" },
	{ 0x32, "Previous Channel" },
	{ 0x33, "Sound Select" },
	{ 0x34, "Input Select" },
	{ 0x35, "Display Information" },
	{ 0x36, "Help" },
	{ 0x37, "Page Up" },
	{ 0x38, "Page Down" },
	{ 0x40, "Power" },
	{ 0x41, "Volume Up" },
	{ 0x42, "Volume Down" },
	{ 0x43, "Mute" },
	{ 0x44, "Play" },
	{ 0x45, "Stop" },
	{ 0x46, "Pause" },
	{ 0x47, "Record" },
	{ 0x48, "Rewind" },
	{ 0x49, "Fast forward" },
	{ 0x4A, "Eject" },
	{ 0x4B, "Forward" },
	{ 0x4C, "Backward" },
	{ 0x4D, "Stop-Record" },
	{ 0x4E, "Pause-Record" },
	{ 0x50, "Angle" },
	{ 0x51, "Sub picture" },
	{ 0x52, "Video on Demand" },
	{ 0x53, "Electronic Program Guide" },
	{ 0x54, "Timer Programming" },
	{ 0x55, "Initial Configuration" },
	{ 0x60, "Play Function" },
	{ 0x61, "Pause-Play Function" },
	{ 0x62, "Record Function" },
	{ 0x63, "Pause-Record Function" },
	{ 0x64, "Stop Function" },
	{ 0x65, "Mute Function" },
	{ 0x66, "Restore Volume Function" },
	{ 0x67, "Tune Function" },
	{ 0x68, "Select Media Function" },
	{ 0x69, "Select A/V Input Function" },
	{ 0x6A, "Select Audio Input Function" },
	{ 0x6B, "Power Toggle Function" },
	{ 0x6C, "Power Off Function" },
	{ 0x6D, "Power On Function" },
	{ 0x71, "F1 (Blue)" },
	{ 0x72, "F2 (Red)" },
	{ 0x73, "F3 (Green)" },
	{ 0x74, "F4 (Yellow)" },
	{ 0x75, "F5" },
	{ 0x76, "Data" },
};

static int hf_cec_vendor_command = -1;

static int hf_cec_vendor_id = -1;
static const value_string cec_vendor_id[] = {
	{ 0x000000, "Unknown" },
	{ 0x000039, "Toshiba" },
	{ 0x0000F0, "Samsung" },
	{ 0x0005CD, "Denon" },
	{ 0x000678, "Marantz" },
	{ 0x000982, "Loewe" },
	{ 0x0009B0, "Onkyo" },
	{ 0x000CB8, "Medion" },
	{ 0x000CE7, "Toshiba 2" },
	{ 0x001582, "Pulse-Eight" },
	{ 0x001950, "Harman-Kardon 2" },
	{ 0x001A11, "Google" },
	{ 0x0020C7, "Akai" },
	{ 0x002467, "AOC" },
	{ 0x008045, "Panasonic" },
	{ 0x00903E, "Philips" },
	{ 0x009053, "Daewoo" },
	{ 0x00A0DE, "Yamaha" },
	{ 0x00D0D5, "Grundig" },
	{ 0x00E036, "Pioneer" },
	{ 0x00E091, "LG" },
	{ 0x08001F, "Sharp" },
	{ 0x080046, "Sony" },
	{ 0x18C086, "Broadcom" },
	{ 0x6B746D, "Vizio" },
	{ 0x8065E9, "Benq" },
	{ 0x9C645E, "Harman-Kardon" },
};

static int hf_cec_version = -1;
static const value_string cec_version[] = {
	{ 0x00, "1.1" },
	{ 0x01, "1.2" },
	{ 0x02, "1.2a" },
	{ 0x03, "1.3" },
	{ 0x04, "1.3a" },
	{ 0x05, "1.4" },
};

static expert_field ei_cec_feature_abort = EI_INIT;
static expert_field ei_cec_extra_bytes = EI_INIT;
static expert_field ei_cec_poll = EI_INIT;

void proto_register_cec(void);
void proto_reg_handoff_cec(void);
static void dissect_cec(tvbuff_t *, packet_info *, proto_tree *);
static guint8 add_parameters_cec(tvbuff_t *, packet_info *, proto_tree *);
static void expert_add_info_cec(tvbuff_t *, packet_info *, proto_tree *, proto_item *, guint8 bytes);

void proto_register_cec(void)
{
	static hf_register_info hf[] = {
		{
			&hf_cec_abort_reason,
			{
				"Abort Reason", "cec.params.abort_reason",
				FT_UINT8, BASE_DEC,
				VALS(cec_abort_reason), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_analogue_broadcast_type,
			{
				"Analogue Broadcast Type", "cec.params.analogue_bcast_type",
				FT_UINT8, BASE_HEX,
				VALS(cec_analogue_broadcast_type), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_analogue_frequency,
			{
				"Analogue Frequency", "cec.params.analog_freq",
				FT_UINT16, BASE_CUSTOM,
				CF_FUNC(cec_fmt_analogue_frequency), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_audio_mute_status,
			{
				"Audio Mute", "cec.params.audio_mute",
				FT_BOOLEAN, BASE_DEC,
				VALS(cec_audio_mute_status), 0x80,
				NULL, HFILL
			},
		},
		{
			&hf_cec_audio_rate,
			{
				"Audio Rate", "cec.params.audio_status.rate",
				FT_UINT8, BASE_HEX,
				VALS(cec_audio_rate), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_audio_status,
			{
				"Audio Status", "cec.audio_status",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_audio_volume_status,
			{
				"Audio Volume Status", "cec.params.audio_status.vol",
				FT_UINT8, BASE_CUSTOM,
				CF_FUNC(cec_fmt_audio_volume_status), 0x7F,
				NULL, HFILL
			},
		},
		{
			&hf_cec_broadcast_system,
			{
				"Broadcast System", "cec.params.bcast_sys",
				FT_UINT8, BASE_HEX,
				VALS(cec_broadcast_system), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_cdc_message,
			{
				"CDC Message", "cec.params.cdc_msg",
				FT_UINT8, BASE_HEX,
				VALS(cec_cdc_message), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_deck_control_mode,
			{
				"Deck Control Mode", "cec.params.deck_ctrl_mode",
				FT_UINT8, BASE_DEC,
				VALS(cec_deck_control_mode), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_deck_info,
			{
				"Deck Info", "cec.params.deck_info",
				FT_UINT8, BASE_DEC,
				VALS(cec_deck_info), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_destination,
			{
				"Destination", "cec.dst",
				FT_UINT8, BASE_DEC,
				VALS(cec_destination), 0x0F,
				NULL, HFILL
			},
		},
		{
			&hf_cec_device_type,
			{
				"Device Type", "cec.params.dev_type",
				FT_UINT8, BASE_DEC,
				VALS(cec_device_type), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_initiator,
			{
				"Source", "cec.src",
				FT_UINT8, BASE_DEC,
				VALS(cec_initiator), 0xF0,
				NULL, HFILL
			},
		},
		{
			&hf_cec_menu_language,
			{
				"Menu Language", "cec.params.menu_lang",
				FT_STRING, STR_ASCII,
				NULL, 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_menu_request_type,
			{
				"Menu Request Type", "cec.params.menu_request_type",
				FT_UINT8, BASE_HEX,
				VALS(cec_menu_request_type), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_menu_state,
			{
				"Menu State", "cec.params.menu_state",
				FT_UINT8, BASE_HEX,
				VALS(cec_menu_state), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_osd_name,
			{
				"OSD Name", "cec.params.osd_name",
				FT_STRING, STR_ASCII,
				NULL, 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_opcode,
			{
				"Opcode", "cec.op",
				FT_UINT8, BASE_HEX,
				VALS(cec_opcode), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_parameters,
			{
				"Parameters", "cec.params",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_physical_address,
			{
				"Physical Address", "cec.params.phy_addr",
				FT_UINT16, BASE_CUSTOM,
				CF_FUNC(cec_fmt_physical_address), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_power_status,
			{
				"Power Status", "cec.params.pwr_status",
				FT_UINT8, BASE_HEX,
				VALS(cec_power_status), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_status_request,
			{
				"Status Request", "cec.params.status_request",
				FT_UINT8, BASE_HEX,
				VALS(cec_status_request), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_system_audio_status,
			{
				"System Audio Status", "cec.params.system_audio_status",
				FT_UINT8, BASE_HEX,
				VALS(cec_system_audio_status), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_user_control_code,
			{
				"User Control Code", "cec.params.usr_ctrl_code",
				FT_UINT8, BASE_HEX,
				VALS(cec_user_control_code), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_vendor_command,
			{
				"Vendor Command", "cec.params.vendor_cmd",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_vendor_id,
			{
				"Vendor ID", "cec.params.vendor_id",
				FT_UINT24, BASE_HEX,
				VALS(cec_vendor_id), 0x00,
				NULL, HFILL
			},
		},
		{
			&hf_cec_version,
			{
				"CEC Version", "cec.params.cec_ver",
				FT_UINT8, BASE_HEX,
				VALS(cec_version), 0x00,
				NULL, HFILL
			},
		},
	};

	static ei_register_info ei[] = {
		{ &ei_cec_extra_bytes, { "cec.extra_bytes", PI_PROTOCOL, PI_WARN, "Extra bytes in packet", EXPFILL }},
		{ &ei_cec_feature_abort, { "cec.feature_abort", PI_SEQUENCE, PI_NOTE, "Feature Abort", EXPFILL }},
		{ &ei_cec_poll, { "cec.poll", PI_SEQUENCE, PI_CHAT, "Poll message", EXPFILL }},
	};

	// Setup protocol subtree array
	static gint *ett[] = {
		&ett_cec,
		&ett_cec_params,
		&ett_cec_audio_status,
	};

        proto_cec = proto_register_protocol(
                "HDMI CEC",
                "CEC",
                "cec"
                );
	expert_cec = expert_register_protocol(proto_cec);

	proto_register_field_array(proto_cec, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_register_field_array(expert_cec, ei, array_length(ei));
	cec_handle = register_dissector("cec", dissect_cec, proto_cec);
}

void proto_reg_handoff_cec(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_CEC, cec_handle);
}

static void dissect_cec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 header;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDMI CEC");

	// Clear out stuff in the info column
	col_clear(pinfo->cinfo, COL_INFO);

	header = tvb_get_guint8(tvb, 0);

	col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%s", val_to_str_const(header >> 4, cec_initiator, "Unknown"));
	col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%s", val_to_str_const(header & 0xF, cec_destination, "Unknown"));

	if (tree) { // We are being asked for details
		proto_item *ti = NULL;
		proto_tree *cec_tree = NULL;
		guint8 bytes = 1;

		ti = proto_tree_add_item(tree, proto_cec, tvb, 0, 1, ENC_NA);

		cec_tree = proto_item_add_subtree(ti, ett_cec);
		proto_tree_add_item(cec_tree, hf_cec_initiator, tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(cec_tree, hf_cec_destination, tvb, 0, 1, ENC_BIG_ENDIAN);

		// If there is no opcode, it is a polling message
		if (tvb_length(tvb) > 1) {
			guint8 oplen;
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_const(tvb_get_guint8(tvb, 1), cec_opcode, "Unknown"));
			proto_tree_add_item(cec_tree, hf_cec_opcode, tvb, 1, 1, ENC_BIG_ENDIAN);
			oplen = add_parameters_cec(tvb, pinfo, cec_tree);
			bytes += 1 + oplen;
			proto_item_set_len(ti, bytes);
		} else {
			col_add_fstr(pinfo->cinfo, COL_INFO, "Poll for %s ", val_to_str_const(header & 0xF, cec_destination, "Unknown"));
		}

		expert_add_info_cec(tvb, pinfo, tree, ti, bytes);
	}
}

static guint8 add_parameters_cec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *params_item = NULL;
	proto_tree *params_tree = NULL;
	guint8 opcode = tvb_get_guint8(tvb, 1);
	guint8 oplen = 0;

	pinfo = pinfo;

	// Should there be any parameters?
	switch(opcode) {
	case 0x00: // Feature Abort
		oplen += 2;
		break;
	case 0x1A: // Give Deck Status
		oplen += 1;
		break;
	case 0x1B: // Deck Status
		oplen += 1;
		break;
	case 0x32: // Set Menu Language
		oplen += 3;
		break;
	case 0x44: // User Control Pressed
		oplen += 1;
		break;
	case 0x47: // Set OSD Name
		oplen += tvb_length(tvb) - 2;
		break;
	case 0x70: // System Audio Mode Request
		if (tvb_length(tvb) >= 4) {
			oplen += 2;
		}
		break;
	case 0x72: // Set System Audio Mode
		oplen += 1;
		break;
	case 0x7A: // Report Audio Status
		oplen += 1;
		break;
	case 0x7E: // System Audio Mode Status
		oplen += 1;
		break;
	case 0x80: // Routing Change
		oplen += 4;
		break;
	case 0x81: // Routing Information
		oplen += 2;
		break;
	case 0x82: // Active Source
		oplen += 2;
		break;
	case 0x84: // Report Physical Address
		oplen += 3;
		break;
	case 0x87: // Device Vendor ID
		oplen += 3;
		break;
	case 0x89: // Vendor Command
		oplen += tvb_length(tvb) - 2;
		break;
	case 0x8D: // Menu Request
		oplen += 1;
		break;
	case 0x8E: // Menu Status
		oplen += 1;
		break;
	case 0x90: // Report Device Power Status
		oplen += 1;
		break;
	case 0x9D: // Inactive Source
		oplen += 2;
		break;
	case 0x9E: // CEC Version
		oplen += 1;
		break;
	case 0xA0: // Vendor Command With ID
		oplen += tvb_length(tvb) - 2;
		break;
	default: // No Operands
		return oplen;
	}

	params_item = proto_tree_add_item(tree, hf_cec_parameters, tvb, 2, oplen, ENC_NA);
	params_tree = proto_item_add_subtree(params_item, ett_cec_params);
	proto_item_set_text(params_item, "Parameters: (%u bytes)", oplen);

	switch(opcode) {
	case 0x00: // Feature Abort
		proto_tree_add_item(params_tree, hf_cec_opcode, tvb, 2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(params_tree, hf_cec_abort_reason, tvb, 3, 1, ENC_BIG_ENDIAN);
		break;
	case 0x1A: // Give Deck Status
		proto_tree_add_item(params_tree, hf_cec_status_request, tvb, 2, 1, ENC_BIG_ENDIAN);
		break;
	case 0x1B: // Deck Status
		proto_tree_add_item(params_tree, hf_cec_deck_info, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "is '%s' ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_deck_info, "Unknown"));
		break;
	case 0x32: // Set Menu Language
		proto_tree_add_item(params_tree, hf_cec_menu_language, tvb, 2, 3, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "to '%.3s' ", tvb_get_string_enc(wmem_packet_scope(), tvb, 2, 3, ENC_ASCII | ENC_NA));
		break;
	case 0x44: // User Control Pressed
		proto_tree_add_item(params_tree, hf_cec_user_control_code, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "'%s' button ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_user_control_code, "Unknown"));
		break;
	case 0x47: // Set OSD Name
		proto_tree_add_item(params_tree, hf_cec_osd_name, tvb, 2, oplen, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "to '%.*s' ", oplen, tvb_get_string_enc(wmem_packet_scope(), tvb, 2, oplen, ENC_ASCII | ENC_NA));
		break;
	case 0x70: // System Audio Mode Request
		if (tvb_length(tvb) >= 4) {
			proto_tree_add_item(params_tree, hf_cec_physical_address, tvb, 2, 2, ENC_BIG_ENDIAN);
			{
				gchar addr[8];
				cec_fmt_physical_address(addr, tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN));
				col_append_fstr(pinfo->cinfo, COL_INFO, "at %s ", addr);
			}
		}
		else {
			col_append_fstr(pinfo->cinfo, COL_INFO, "Shutdown ");
		}
		break;
	case 0x72: // Set System Audio Mode
		proto_tree_add_item(params_tree, hf_cec_system_audio_status, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "to '%s' ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_system_audio_status, "Unknown"));
		break;
	case 0x7A: // Report Audio Status
		{
			proto_item *audio_item = proto_tree_add_item(params_tree, hf_cec_audio_status, tvb, 2, 1, ENC_NA);
			proto_tree *audio_tree = proto_item_add_subtree(audio_item, ett_cec_audio_status);
			if (tvb_get_guint8(tvb, 2) & 0x80) {
				proto_item_set_text(audio_item, "Audio Status: Muted");
				col_append_fstr(pinfo->cinfo, COL_INFO, "is Muted ");
			}
			else {
				gchar vol[11];
				cec_fmt_audio_volume_status(vol, tvb_get_guint8(tvb, 2));
				proto_item_set_text(audio_item, "Audio Status: %s Volume", vol);
				col_append_fstr(pinfo->cinfo, COL_INFO, "is at %s Volume ", vol);
			}
			proto_tree_add_item(audio_tree, hf_cec_audio_mute_status, tvb, 2, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(audio_tree, hf_cec_audio_volume_status, tvb, 2, 1, ENC_BIG_ENDIAN);
		}
		break;
	case 0x7E: // System Audio Mode Status
		proto_tree_add_item(params_tree, hf_cec_system_audio_status, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "is '%s' ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_system_audio_status, "Unknown"));
		break;
	case 0x80: // Routing Change
		proto_tree_add_item(params_tree, hf_cec_physical_address, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(params_tree, hf_cec_physical_address, tvb, 4, 2, ENC_BIG_ENDIAN);
		{
			gchar orig_addr[8];
			gchar new_addr[8];
			cec_fmt_physical_address(orig_addr, tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN));
			cec_fmt_physical_address(new_addr, tvb_get_guint16(tvb, 4, ENC_BIG_ENDIAN));
			col_append_fstr(pinfo->cinfo, COL_INFO, "from %s to %s ", orig_addr, new_addr);
		}
		break;
	case 0x81: // Routing Information
		proto_tree_add_item(params_tree, hf_cec_physical_address, tvb, 2, 2, ENC_BIG_ENDIAN);
		{
			gchar addr[8];
			cec_fmt_physical_address(addr, tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN));
		}
		break;
	case 0x82: // Active Source
		proto_tree_add_item(params_tree, hf_cec_physical_address, tvb, 2, 2, ENC_BIG_ENDIAN);
		{
			gchar addr[8];
			cec_fmt_physical_address(addr, tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN));
			col_append_fstr(pinfo->cinfo, COL_INFO, "to %s ", addr);
		}
		break;
	case 0x84: // Report Physical Address
		proto_tree_add_item(params_tree, hf_cec_physical_address, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(params_tree, hf_cec_device_type, tvb, 4, 1, ENC_BIG_ENDIAN);
		{
			gchar addr[8];
			cec_fmt_physical_address(addr, tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN));
			col_append_fstr(pinfo->cinfo, COL_INFO, "of %s ", addr);
		}
		break;
	case 0x87: // Device Vendor ID
		proto_tree_add_item(params_tree, hf_cec_vendor_id, tvb, 2, 3, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "is %s ", val_to_str_const(tvb_get_guint24(tvb, 2, ENC_BIG_ENDIAN), cec_vendor_id, "Unknown"));
		break;
	case 0x89: // Vendor Command
		proto_tree_add_item(params_tree, hf_cec_vendor_command, tvb, 2, oplen, ENC_BIG_ENDIAN);
		break;
	case 0x8D: // Menu Request
		proto_tree_add_item(params_tree, hf_cec_menu_request_type, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "to %s ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_menu_request_type, "Unknown"));
		break;
	case 0x8E: // Menu Status
		proto_tree_add_item(params_tree, hf_cec_menu_state, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "is in a(n) %s state ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_menu_state, "Unknown"));
		break;
	case 0x90: // Report Device Power Status
		proto_tree_add_item(params_tree, hf_cec_power_status, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "is %s ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_power_status, "Unknown"));
		break;
	case 0x9D: // Inactive Source
		proto_tree_add_item(params_tree, hf_cec_physical_address, tvb, 2, 2, ENC_BIG_ENDIAN);
		{
			gchar addr[8];
			cec_fmt_physical_address(addr, tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN));
			col_append_fstr(pinfo->cinfo, COL_INFO, "at %s ", addr);
		}
		break;
	case 0x9E: // CEC Version
		proto_tree_add_item(params_tree, hf_cec_version, tvb, 2, 1, ENC_BIG_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, "is %s ", val_to_str_const(tvb_get_guint8(tvb, 2), cec_version, "Unknown"));
		break;
	case 0xA0: // Vendor Command With ID
		proto_tree_add_item(params_tree, hf_cec_vendor_id, tvb, 2, 3, ENC_BIG_ENDIAN);
		proto_tree_add_item(params_tree, hf_cec_vendor_command, tvb, 5, oplen - 3, ENC_BIG_ENDIAN);
		break;
	}

	return oplen;
}

static void expert_add_info_cec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *ti, guint8 bytes)
{
	if (tvb_length(tvb) == 1) {
		expert_add_info_format(pinfo, ti, &ei_cec_poll, "Poll for %s", val_to_str_const(tvb_get_guint8(tvb, 0) & 0xF, cec_destination, "Unknown"));
	} else if (tvb_get_guint8(tvb, 1) == 0x00) {
		expert_add_info(pinfo, ti, &ei_cec_feature_abort);
	} 

	if (tvb_length(tvb) > bytes)
	{
		unsigned int extra = tvb_length(tvb) - bytes;
		col_append_fstr(pinfo->cinfo, COL_INFO, "[Extra %u bytes] ", extra);
		proto_tree_add_expert_format(tree, pinfo, &ei_cec_extra_bytes, tvb, bytes, extra, "Extra %u bytes in packet", extra);
	}
}
