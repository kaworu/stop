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

static unsigned long int parseUevent(FILE * file, char *key) {
   char line[100];
   unsigned long int dValue = 0;

   while (fgets(line, sizeof line, file)) {
      if (strncmp(line, key, strlen(key)) == 0) {
         char *value;
         value = strtok(line, "=");
         value = strtok(NULL, "=");
         dValue = atoi(value);
         break;
      }
   }
   return dValue;
}

static unsigned long int parseBatInfo(const char *fileName, const unsigned short int lineNum, const unsigned short int wordNum) {
   const DIR *batteryDir;
   const struct dirent *dirEntries;

   const char batteryPath[] = PROCDIR "/acpi/battery/";
   batteryDir = opendir(batteryPath);

   if (batteryDir == NULL) {
      return 0;
   }

   char *entryName;
   typedef struct listLbl {
      char *content;
      struct listLbl *next;
   } list;

   list *myList = NULL;
   list *newEntry;

   /*
      Some of this is based off of code found in kismet (they claim it came from gkrellm).
      Written for multi battery use...
    */
   for (dirEntries = readdir((DIR *) batteryDir); dirEntries; dirEntries = readdir((DIR *) batteryDir)) {
      entryName = (char *) dirEntries->d_name;

      if (strncmp(entryName, "BAT", 3))
         continue;

      newEntry = calloc(1, sizeof(list));
      newEntry->next = myList;
      newEntry->content = entryName;
      myList = newEntry;
   }

   unsigned long int total = 0;
   for (newEntry = myList; newEntry; newEntry = newEntry->next) {
      const char infoPath[30];
      const FILE *file;
      char line[50];

      snprintf((char *) infoPath, sizeof infoPath, "%s%s/%s", batteryPath, newEntry->content, fileName);

      if ((file = fopen(infoPath, "r")) == NULL) {
         return 0;
      }

      for (unsigned short int i = 0; i < lineNum; i++) {
         fgets(line, sizeof line, (FILE *) file);
      }

      fclose((FILE *) file);

      const char *foundNumTmp = String_getToken(line, wordNum);
      const unsigned long int foundNum = atoi(foundNumTmp);
      free((char *) foundNumTmp);

      total += foundNum;
   }

   free(myList);
   free(newEntry);
   closedir((DIR *) batteryDir);
   return total;
}

static ACPresence chkIsOnline(void) {
    if (Sysctl.geti("hw.acpi.acline"))
        return (AC_PRESENT);
    else
        return (AC_ABSENT);
}

/* still named getProcBatData event if it doesn't use Proc, just to ease merge. */
static double getProcBatData(void) {
   return ((double)Sysctl.geti("hw.acpi.battery.life"));
}

/* dummy */
static double getSysBatData(void) {
    return (0);
}

static void BatteryMeter_setValues(Meter * this, char *buffer, int len) {
   double percent = getProcBatData();
   if (percent == 0) {
      percent = getSysBatData();
      if (percent == 0) {
         snprintf(buffer, len, "n/a");
         return;
      }
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
