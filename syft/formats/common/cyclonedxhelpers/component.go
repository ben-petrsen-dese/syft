package cyclonedxhelpers

import (
	"reflect"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/common"
	"github.com/anchore/syft/syft/pkg"
)

func encodeComponent(p pkg.Package) cyclonedx.Component {
	props := encodeProperties(p, "syft:package")
	props = append(props, encodeCPEs(p)...)
	locations := p.Locations.ToSlice()
	if len(locations) > 0 {
		props = append(props, encodeProperties(locations, "syft:location")...)
	}
	if hasMetadata(p) {
		props = append(props, encodeProperties(p.Metadata, "syft:metadata")...)
	}

	var properties *[]cyclonedx.Property
	if len(props) > 0 {
		properties = &props
	}

	componentType := cyclonedx.ComponentTypeLibrary
	if p.Type == pkg.BinaryPkg {
		componentType = cyclonedx.ComponentTypeApplication
	}

	return cyclonedx.Component{
		Type:               componentType,
		Name:               p.Name,
		Group:              encodeGroup(p),
		Version:            p.Version,
		PackageURL:         p.PURL,
		Licenses:           encodeLicenses(p),
		CPE:                encodeSingleCPE(p),
		Author:             encodeAuthor(p),
		Publisher:          encodePublisher(p),
		Description:        encodeDescription(p),
		ExternalReferences: encodeExternalReferences(p),
		Properties:         properties,
		BOMRef:             deriveBomRef(p),
	}
}

func deriveBomRef(p pkg.Package) string {
	// try and parse the PURL if possible and append syft id to it, to make
	// the purl unique in the BOM.
	// TODO: In the future we may want to dedupe by PURL and combine components with
	// the same PURL while preserving their unique metadata.
	if parsedPURL, err := packageurl.FromString(p.PURL); err == nil {
		parsedPURL.Qualifiers = append(parsedPURL.Qualifiers, packageurl.Qualifier{Key: "package-id", Value: string(p.ID())})
		return parsedPURL.ToString()
	}
	// fallback is to use strictly the ID if there is no valid pURL
	return string(p.ID())
}

func hasMetadata(p pkg.Package) bool {
	return p.Metadata != nil
}

func decodeComponent(c *cyclonedx.Component) *pkg.Package {
	values := map[string]string{}
	println("Properties")
	for _, p := range *c.ExternalReferences {
		println(p.URL)
	}
	if c.Properties != nil {
		for _, p := range *c.Properties {
			values[p.Name] = p.Value
		}
	}

	p := &pkg.Package{
		Name:         c.Name,
		Version:      c.Version,
		Locations:    decodeLocations(values),
		Licenses:     pkg.NewLicenseSet(decodeLicenses(c)...),
		CPEs:         decodeCPEs(c),
		PURL:         c.PackageURL,
		MetadataType: pkg.MetadataType(pkg.PythonPackageMetadataType),
	}
	print("Hello: ")
	println(p.Name)

	common.DecodeInto(p, values, "syft:package", CycloneDXFields)

	print("Wolrd: ")
	println(p.MetadataType)
	println(c.Properties)

	p.MetadataType = pkg.CleanMetadataType(p.MetadataType)

	p.Metadata = decodePackageMetadata(values, c, p.MetadataType)

	// print("Wolrd: ")
	// println(p.MetadataType)

	if p.Type == "" {
		p.Type = pkg.TypeFromPURL(p.PURL)
	}

	if p.Language == "" {
		p.Language = pkg.LanguageFromPURL(p.PURL)
	}

	return p
}

func decodeLocations(vals map[string]string) file.LocationSet {
	v := common.Decode(reflect.TypeOf([]file.Location{}), vals, "syft:location", CycloneDXFields)
	out, ok := v.([]file.Location)
	if !ok {
		out = nil
	}
	return file.NewLocationSet(out...)
}

func decodePackageMetadata(vals map[string]string, c *cyclonedx.Component, typ pkg.MetadataType) interface{} {
	println("KIRB")
	println(vals)
	for key, val := range vals {
		println(key, ":", val)
	}
	println(typ)
	println(c.Properties)
	println(c.Publisher)
	if typ != "" { //} && c.Properties != nil {
		println("SOMETHING")
		metaTyp, ok := pkg.MetadataTypeByName[typ]
		println(metaTyp)
		println("ok")
		println(ok)
		if !ok {
			return nil
		}
		metaPtrTyp := reflect.PtrTo(metaTyp)
		println("metaPtrTyp")
		metaPtr := common.Decode(metaPtrTyp, vals, "syft:metadata", CycloneDXFields)

		println("AGAIN")
		// Map all explicit metadata properties
		decodeAuthor(c.Author, metaPtr)
		decodeGroup(c.Group, metaPtr)
		decodePublisher(c.Publisher, metaPtr)
		decodeDescription(c.Description, metaPtr)
		println("BEN")
		// println(c.ExternalReferences)
		println(metaPtr)
		decodeExternalReferences(c, metaPtr)

		// return the actual interface{} -> struct ... not interface{} -> *struct
		return common.PtrToStruct(metaPtr)
	}
	println("RETURNING NIL")
	return nil
}
