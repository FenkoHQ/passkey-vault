// Select screenshot-sized devices from simctl's available-device inventory.
const models = { phone: /iPhone.*Pro Max/, tablet: /iPad Pro.*13-inch/ };
const model = models[process.argv[2]];
if (!model) throw new Error('Choose phone or tablet');
let input = '';
for await (const chunk of process.stdin) input += chunk;
const devices = Object.values(JSON.parse(input).devices).flat();
const device = devices.find((item) => model.test(item.name) && item.state === 'Shutdown');
if (!device) throw new Error(`No available ${process.argv[2]} simulator matches the screenshot size`);
process.stdout.write(device.udid);
