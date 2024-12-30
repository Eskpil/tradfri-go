package model

import (
	"time"
)

// ToDeviceResponse transforms the passed device into either a BulbResponse or BlindResponse. (more needed)
func ToDeviceResponse(device Device) interface{} {
	if device.LightControl != nil && len(device.LightControl) > 0 {

		return BulbResponse{
			DeviceMetadata: DeviceMetadata{
				Name:   device.Name,
				Id:     device.DeviceId,
				Type:   device.Metadata.TypeName,
				Vendor: device.Metadata.Vendor},
			Power:      device.LightControl[0].Power == 1,
			CIE_1931_X: device.LightControl[0].CIE_1931_X,
			CIE_1931_Y: device.LightControl[0].CIE_1931_Y,
			RGB:        device.LightControl[0].RGBHex,
			Dimmer:     device.LightControl[0].Dimmer,
		}
	}

	// blinds
	if device.BlindControl != nil && len(device.BlindControl) > 0 {
		return BlindResponse{
			DeviceMetadata: DeviceMetadata{
				Name:    device.Name,
				Id:      device.DeviceId,
				Type:    device.Metadata.TypeName,
				Vendor:  device.Metadata.Vendor,
				Battery: device.Metadata.Battery,
			},
			Position: device.BlindControl[0].Position,
		}
	}

	// power outlet
	if len(device.OutletControl) > 0 {
		return PowerPlugResponse{
			DeviceMetadata: DeviceMetadata{
				Name:   device.Name,
				Id:     device.DeviceId,
				Type:   device.Metadata.TypeName,
				Vendor: device.Metadata.Vendor,
			},
			Power: device.OutletControl[0].Power == 1,
		}
	}

	return nil
}

// ToGroupResponse transforms a group into a response format more suitable for JSON serialization
func ToGroupResponse(group Group) GroupResponse {
	gr := GroupResponse{
		Id:         group.DeviceId,
		Power:      group.Power,
		Created:    time.Unix(int64(group.CreatedAt), 0).Format(time.RFC3339),
		DeviceList: group.Content.DeviceList.DeviceIds,
	}
	return gr
}
