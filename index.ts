import {DMLog} from "./utils/dmlog";
import {AntiDebug} from "./utils/android/anti/AntiDebug";
import {AndOperations} from "./utils/android/andOperations";
const and = require('./utils/android/*');

function main() {
    DMLog.d('MAIN', 'HELLO FridaContainer');

    AntiDebug.anti_ptrace();
    AntiDebug.anti_fgets();
    // and.anti.AntiDebug.anti_fgets();
}

Java.perform(function () {
    main();
});
