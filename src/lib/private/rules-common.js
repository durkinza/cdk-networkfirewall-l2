"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.castAddressProperty = void 0;
/**
 * Cast a string (of) cidr(s) to AddressProperty
 */
function castAddressProperty(addresses) {
    let locations = [];
    if (addresses !== undefined) {
        let address;
        for (address of addresses) {
            locations.push({ addressDefinition: address });
        }
    }
    return locations;
}
exports.castAddressProperty = castAddressProperty;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicnVsZXMtY29tbW9uLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsicnVsZXMtY29tbW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUVBOztHQUVHO0FBQ0gsU0FBZ0IsbUJBQW1CLENBQUMsU0FBNEI7SUFDOUQsSUFBSSxTQUFTLEdBQWtDLEVBQUUsQ0FBQztJQUNsRCxJQUFJLFNBQVMsS0FBSyxTQUFTLEVBQUU7UUFDM0IsSUFBSSxPQUFjLENBQUM7UUFDbkIsS0FBSyxPQUFPLElBQUksU0FBUyxFQUFFO1lBQ3pCLFNBQVMsQ0FBQyxJQUFJLENBQUMsRUFBRSxpQkFBaUIsRUFBRSxPQUFPLEVBQUUsQ0FBQyxDQUFDO1NBQ2hEO0tBQ0Y7SUFDRCxPQUFPLFNBQVMsQ0FBQztBQUNuQixDQUFDO0FBVEQsa0RBU0MiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBDZm5SdWxlR3JvdXAgfSBmcm9tICdhd3MtY2RrLWxpYi9hd3MtbmV0d29ya2ZpcmV3YWxsJztcblxuLyoqXG4gKiBDYXN0IGEgc3RyaW5nIChvZikgY2lkcihzKSB0byBBZGRyZXNzUHJvcGVydHlcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNhc3RBZGRyZXNzUHJvcGVydHkoYWRkcmVzc2VzOnN0cmluZ1tdfHVuZGVmaW5lZCk6Q2ZuUnVsZUdyb3VwLkFkZHJlc3NQcm9wZXJ0eVtdIHtcbiAgbGV0IGxvY2F0aW9uczpDZm5SdWxlR3JvdXAuQWRkcmVzc1Byb3BlcnR5W10gPSBbXTtcbiAgaWYgKGFkZHJlc3NlcyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgbGV0IGFkZHJlc3M6c3RyaW5nO1xuICAgIGZvciAoYWRkcmVzcyBvZiBhZGRyZXNzZXMpIHtcbiAgICAgIGxvY2F0aW9ucy5wdXNoKHsgYWRkcmVzc0RlZmluaXRpb246IGFkZHJlc3MgfSk7XG4gICAgfVxuICB9XG4gIHJldHVybiBsb2NhdGlvbnM7XG59XG4iXX0=