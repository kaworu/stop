/*
  htop
  (C) 2004-2006 Hisham H. Muhammad
  Released under the GNU GPL, see the COPYING file
  in the source distribution for its full text.

  This "Meter" written by Ian P. Hands (iphands@gmail.com, ihands@redhat.com).
*/

#include "BatteryMeter.h"
#include "Meter.h"
#include "ProcessList.h"
#include "CRT.h"
#include "String.h"
#include "Sysctl.h"
#include "debug.h"

/*{

typedef enum ACPresence_ {
   AC_ABSENT,
   AC_PRESENT,
   AC_ERROR
} ACPresence;

}*/

int BatteryMeter_attributes[] = {
   BATTERY
};

static ACPresence chkIsOnline(void) {
    if (htop_sysctl_int("hw.acpi.acline"))
        return (AC_PRESENT);
    else
        return (AC_ABSENT);
}

static double getBatData(void) {
   return ((double)htop_sysctl_int("hw.acpi.battery.life"));
}

static void BatteryMeter_setValues(Meter * this, char *buffer, int len) {
   double percent = getBatData();
   if (percent == 0) {
         snprintf(buffer, len, "n/a");
         return;
   }

   this->values[0] = percent;

   char *onAcText, *onBatteryText, *unknownText;

   unknownText = "%.1f%%";
   if (this->mode == TEXT_METERMODE) {
      onAcText = "%.1f%% (Running on A/C)";
      onBatteryText = "%.1f%% (Running on battery)";
   } else {
      onAcText = "%.1f%%(A/C)";
      onBatteryText = "%.1f%%(bat)";
   }

   ACPresence isOnLine = chkIsOnline();

   if (isOnLine == AC_PRESENT) {
      snprintf(buffer, len, onAcText, percent);
   } else if (isOnLine == AC_ABSENT) {
      snprintf(buffer, len, onBatteryText, percent);
   } else {
      snprintf(buffer, len, unknownText, percent);
   }

   return;
}

MeterType BatteryMeter = {
   .setValues = BatteryMeter_setValues,
   .display = NULL,
   .mode = TEXT_METERMODE,
   .items = 1,
   .total = 100.0,
   .attributes = BatteryMeter_attributes,
   .name = "Battery",
   .uiName = "Battery",
   .caption = "Battery: "
};
