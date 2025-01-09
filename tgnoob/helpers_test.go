// Copyright 2019 Aporeto Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tgnoob

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"reflect"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_GenerateCertificate(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		outputFolder, _ := os.MkdirTemp("", "certificates")

		Convey("If no name is provided, it should fail", func() {
			err := GenerateCertificate(
				"",           // name
				"commonName", // commonName
				"password",   // password
				true,         // isCA
				true,         // authServer
				true,         // authClient
				true,         // authEmail
				false,        // p12
				"",           // p12Pass
				outputFolder, // out
				false,        // force
				algoECDSA,    // algo
				"",           // signingCertPath
				"",           // signingCertKeyPath
				"",           // signingCertKeyPass
				[]string{},   // country
				[]string{},   // state
				[]string{},   // city
				[]string{},   // address
				[]string{},   // zipCode
				[]string{},   // org
				[]string{},   // orgUnit
				[]string{},   // dns
				[]string{},   // ips
				time.Second,  // duration
				[]string{},   // policies
				[]string{},   // emails
				[]string{},   // extensions
				[]string{},   // extranames,
			)
			So(err, ShouldNotBeNil)
		})

		Convey("If no common name is provided, it should not fail", func() {
			err := GenerateCertificate(
				"name",       // name
				"",           // commonName
				"password",   // password
				true,         // isCA
				true,         // authServer
				true,         // authClient
				true,         // authEmail
				false,        // p12
				"",           // p12Pass
				outputFolder, // out
				false,        // force
				algoECDSA,    // algo
				"",           // signingCertPath
				"",           // signingCertKeyPath
				"",           // signingCertKeyPass
				[]string{},   // country
				[]string{},   // state
				[]string{},   // city
				[]string{},   // address
				[]string{},   // zipCode
				[]string{},   // org
				[]string{},   // orgUnit
				[]string{},   // dns
				[]string{},   // ips
				time.Second,  // duration
				[]string{},   // policies
				[]string{},   // emails
				[]string{},   // extensions
				[]string{},   // extranames,
			)
			So(err, ShouldBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder) // nolint
		})
	})
}
func Test_GenerateCSR(t *testing.T) {
	Convey("Given an outputfolder", t, func() {

		outputFolder, _ := os.MkdirTemp("", "certificates")

		Convey("I should be able to generate a csr with a certificate", func() {

			var err error
			singingCertPath, signingCertKeyPath, err := CreateCA("ca-acme", "acme", "passwd", outputFolder)
			So(err, ShouldBeNil)

			err = GenerateCSR(
				"demo",             // name
				"",                 // commonName
				singingCertPath,    // cert
				signingCertKeyPath, // certKey
				"passwd",           // certKeyPass
				outputFolder,       // out
				true,               // force
				algoRSA,            // algo
				nil,                // country
				nil,                // state
				nil,                // city
				nil,                // address
				nil,                // zipCode
				nil,                // org
				nil,                // orgUnit
				nil,                // dns
				nil,                // ips
				[]string{},         // policies
				nil,                // emails
			)
			So(err, ShouldBeNil)
		})

		Convey("I should be able to generate a csr without a certificate", func() {
			err := GenerateCSR(
				"demo",                  // name
				"demo",                  // commonName
				"",                      // cert
				"",                      // certKey
				"",                      // certKeyPass
				outputFolder,            // out
				true,                    // force
				algoRSA,                 // algo
				[]string{"us"},          // country
				[]string{"ca"},          // state
				[]string{"sanjose"},     // city
				[]string{"demo street"}, // address
				[]string{"95000"},       // zipCode
				[]string{"demo"},        // org
				[]string{"org-demo"},    // orgUnit
				[]string{"demo.com"},    // dns
				[]string{"192.169.0.1"}, // ips
				[]string{},              // policies
				[]string{},              // emails
			)
			So(err, ShouldBeNil)
		})

		Reset(func() {
			os.Remove(outputFolder) // nolint
		})
	})
}

func Test_makeExtensions(t *testing.T) {
	type args struct {
		extensions []string
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1      []pkix.Extension
		wantErr    bool
		inspectErr func(err error, t *testing.T) //use for more precise error evaluation after test
	}{
		{
			"basic",
			func(*testing.T) args {
				return args{
					extensions: []string{"1.2.3:coucou bro"},
				}
			},
			[]pkix.Extension{
				{
					Id:    asn1.ObjectIdentifier{1, 2, 3},
					Value: []byte("coucou bro"),
				},
			},
			false,
			nil,
		},
		{
			"basic multiple",
			func(*testing.T) args {
				return args{
					extensions: []string{"1.2.3:coucou bro", "1.2.2:coucou2"},
				}
			},
			[]pkix.Extension{
				{
					Id:    asn1.ObjectIdentifier{1, 2, 3},
					Value: []byte("coucou bro"),
				},
				{
					Id:    asn1.ObjectIdentifier{1, 2, 2},
					Value: []byte("coucou2"),
				},
			},
			false,
			nil,
		},
		{
			"invalid format",
			func(*testing.T) args {
				return args{
					extensions: []string{"coucou"},
				}
			},
			nil,
			true,
			func(err error, t *testing.T) {
				exp := "invalid extension string 'coucou'"
				if err.Error() != exp {
					t.Fatalf("invalid error: expected '%s' got '%s'", exp, err)
				}
			},
		},
		{
			"invalid oid",
			func(*testing.T) args {
				return args{
					extensions: []string{"coucou:coucou"},
				}
			},
			nil,
			true,
			func(err error, t *testing.T) {
				exp := "'coucou' is not a valid OID for extension 'coucou:coucou'"
				if err.Error() != exp {
					t.Fatalf("invalid error: expected '%s' got '%s'", exp, err)
				}
			},
		},
		{
			"invalid oid 2",
			func(*testing.T) args {
				return args{
					extensions: []string{"1.coucou.3:coucou"},
				}
			},
			nil,
			true,
			func(err error, t *testing.T) {
				exp := "'coucou' is not a valid OID for extension '1.coucou.3:coucou'"
				if err.Error() != exp {
					t.Fatalf("invalid error: expected '%s' got '%s'", exp, err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1, err := makeExtensions(tArgs.extensions)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("makeExtensions got1 = %v, want1: %v", got1, tt.want1)
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("makeExtensions error = %v, wantErr: %t", err, tt.wantErr)
			}

			if tt.inspectErr != nil {
				tt.inspectErr(err, t)
			}
		})
	}
}
