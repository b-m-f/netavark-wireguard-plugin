//  Much code in this file was taken from the https://github.com/containers/netavark/blob/main/src/network/netlink.rs
//  on the 30.04.23 and comes with the following License
//
//  Changes have been made to add generic socket creation the socket creation, please diff against the repository located above
//  to see all the exact changes
//
//                               Apache License
//                         Version 2.0, January 2004
//                      http://www.apache.org/licenses/
//
// TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
//
// 1. Definitions.
//
//    "License" shall mean the terms and conditions for use, reproduction,
//    and distribution as defined by Sections 1 through 9 of this document.
//
//    "Licensor" shall mean the copyright owner or entity authorized by
//    the copyright owner that is granting the License.
//
//    "Legal Entity" shall mean the union of the acting entity and all
//    other entities that control, are controlled by, or are under common
//    control with that entity. For the purposes of this definition,
//    "control" means (i) the power, direct or indirect, to cause the
//    direction or management of such entity, whether by contract or
//    otherwise, or (ii) ownership of fifty percent (50%) or more of the
//    outstanding shares, or (iii) beneficial ownership of such entity.
//
//    "You" (or "Your") shall mean an individual or Legal Entity
//    exercising permissions granted by this License.
//
//    "Source" form shall mean the preferred form for making modifications,
//    including but not limited to software source code, documentation
//    source, and configuration files.
//
//    "Object" form shall mean any form resulting from mechanical
//    transformation or translation of a Source form, including but
//    not limited to compiled object code, generated documentation,
//    and conversions to other media types.
//
//    "Work" shall mean the work of authorship, whether in Source or
//    Object form, made available under the License, as indicated by a
//    copyright notice that is included in or attached to the work
//    (an example is provided in the Appendix below).
//
//    "Derivative Works" shall mean any work, whether in Source or Object
//    form, that is based on (or derived from) the Work and for which the
//    editorial revisions, annotations, elaborations, or other modifications
//    represent, as a whole, an original work of authorship. For the purposes
//    of this License, Derivative Works shall not include works that remain
//    separable from, or merely link (or bind by name) to the interfaces of,
//    the Work and Derivative Works thereof.
//
//    "Contribution" shall mean any work of authorship, including
//    the original version of the Work and any modifications or additions
//    to that Work or Derivative Works thereof, that is intentionally
//    submitted to Licensor for inclusion in the Work by the copyright owner
//    or by an individual or Legal Entity authorized to submit on behalf of
//    the copyright owner. For the purposes of this definition, "submitted"
//    means any form of electronic, verbal, or written communication sent
//    to the Licensor or its representatives, including but not limited to
//    communication on electronic mailing lists, source code control systems,
//    and issue tracking systems that are managed by, or on behalf of, the
//    Licensor for the purpose of discussing and improving the Work, but
//    excluding communication that is conspicuously marked or otherwise
//    designated in writing by the copyright owner as "Not a Contribution."
//
//    "Contributor" shall mean Licensor and any individual or Legal Entity
//    on behalf of whom a Contribution has been received by Licensor and
//    subsequently incorporated within the Work.
//
// 2. Grant of Copyright License. Subject to the terms and conditions of
//    this License, each Contributor hereby grants to You a perpetual,
//    worldwide, non-exclusive, no-charge, royalty-free, irrevocable
//    copyright license to reproduce, prepare Derivative Works of,
//    publicly display, publicly perform, sublicense, and distribute the
//    Work and such Derivative Works in Source or Object form.
//
// 3. Grant of Patent License. Subject to the terms and conditions of
//    this License, each Contributor hereby grants to You a perpetual,
//    worldwide, non-exclusive, no-charge, royalty-free, irrevocable
//    (except as stated in this section) patent license to make, have made,
//    use, offer to sell, sell, import, and otherwise transfer the Work,
//    where such license applies only to those patent claims licensable
//    by such Contributor that are necessarily infringed by their
//    Contribution(s) alone or by combination of their Contribution(s)
//    with the Work to which such Contribution(s) was submitted. If You
//    institute patent litigation against any entity (including a
//    cross-claim or counterclaim in a lawsuit) alleging that the Work
//    or a Contribution incorporated within the Work constitutes direct
//    or contributory patent infringement, then any patent licenses
//    granted to You under this License for that Work shall terminate
//    as of the date such litigation is filed.
//
// 4. Redistribution. You may reproduce and distribute copies of the
//    Work or Derivative Works thereof in any medium, with or without
//    modifications, and in Source or Object form, provided that You
//    meet the following conditions:
//
//    (a) You must give any other recipients of the Work or
//        Derivative Works a copy of this License; and
//
//    (b) You must cause any modified files to carry prominent notices
//        stating that You changed the files; and
//
//    (c) You must retain, in the Source form of any Derivative Works
//        that You distribute, all copyright, patent, trademark, and
//        attribution notices from the Source form of the Work,
//        excluding those notices that do not pertain to any part of
//        the Derivative Works; and
//
//    (d) If the Work includes a "NOTICE" text file as part of its
//        distribution, then any Derivative Works that You distribute must
//        include a readable copy of the attribution notices contained
//        within such NOTICE file, excluding those notices that do not
//        pertain to any part of the Derivative Works, in at least one
//        of the following places: within a NOTICE text file distributed
//        as part of the Derivative Works; within the Source form or
//        documentation, if provided along with the Derivative Works; or,
//        within a display generated by the Derivative Works, if and
//        wherever such third-party notices normally appear. The contents
//        of the NOTICE file are for informational purposes only and
//        do not modify the License. You may add Your own attribution
//        notices within Derivative Works that You distribute, alongside
//        or as an addendum to the NOTICE text from the Work, provided
//        that such additional attribution notices cannot be construed
//        as modifying the License.
//
//    You may add Your own copyright statement to Your modifications and
//    may provide additional or different license terms and conditions
//    for use, reproduction, or distribution of Your modifications, or
//    for any such Derivative Works as a whole, provided Your use,
//    reproduction, and distribution of the Work otherwise complies with
//    the conditions stated in this License.
//
// 5. Submission of Contributions. Unless You explicitly state otherwise,
//    any Contribution intentionally submitted for inclusion in the Work
//    by You to the Licensor shall be under the terms and conditions of
//    this License, without any additional terms or conditions.
//    Notwithstanding the above, nothing herein shall supersede or modify
//    the terms of any separate license agreement you may have executed
//    with Licensor regarding such Contributions.
//
// 6. Trademarks. This License does not grant permission to use the trade
//    names, trademarks, service marks, or product names of the Licensor,
//    except as required for reasonable and customary use in describing the
//    origin of the Work and reproducing the content of the NOTICE file.
//
// 7. Disclaimer of Warranty. Unless required by applicable law or
//    agreed to in writing, Licensor provides the Work (and each
//    Contributor provides its Contributions) on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
//    implied, including, without limitation, any warranties or conditions
//    of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
//    PARTICULAR PURPOSE. You are solely responsible for determining the
//    appropriateness of using or redistributing the Work and assume any
//    risks associated with Your exercise of permissions under this License.
//
// 8. Limitation of Liability. In no event and under no legal theory,
//    whether in tort (including negligence), contract, or otherwise,
//    unless required by applicable law (such as deliberate and grossly
//    negligent acts) or agreed to in writing, shall any Contributor be
//    liable to You for damages, including any direct, indirect, special,
//    incidental, or consequential damages of any character arising as a
//    result of this License or out of the use or inability to use the
//    Work (including but not limited to damages for loss of goodwill,
//    work stoppage, computer failure or malfunction, or any and all
//    other commercial damages or losses), even if such Contributor
//    has been advised of the possibility of such damages.
//
// 9. Accepting Warranty or Additional Liability. While redistributing
//    the Work or Derivative Works thereof, You may choose to offer,
//    and charge a fee for, acceptance of support, warranty, indemnity,
//    or other liability obligations and/or rights consistent with this
//    License. However, in accepting such obligations, You may act only
//    on Your own behalf and on Your sole responsibility, not on behalf
//    of any other Contributor, and only if You agree to indemnify,
//    defend, and hold each Contributor harmless for any liability
//    incurred by, or claims asserted against, such Contributor by reason
//    of your accepting any such warranty or additional liability.
//
// END OF TERMS AND CONDITIONS
//
// APPENDIX: How to apply the Apache License to your work.
//
//    To apply the Apache License to your work, attach the following
//    boilerplate notice, with the fields enclosed by brackets "[]"
//    replaced with your own identifying information. (Don't include
//    the brackets!)  The text should be enclosed in the appropriate
//    comment syntax for the file format. We also recommend that a
//    file or class name and description of purpose be included on the
//    same "printed page" as the copyright notice for easier
//    identification within third-party archives.
//
// Copyright [yyyy] [name of copyright owner]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//
//
//
//
//

use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK,
    NLM_F_DUMP, NLM_F_REQUEST,
};

use netlink_sys::constants::NETLINK_GENERIC;

use std::os::unix::prelude::RawFd;

use std::io;

use log::trace;

use netavark::error::{NetavarkError, NetavarkResult};
use netlink_packet_wireguard::nlas::WgDeviceAttrs;
use netlink_packet_wireguard::{Wireguard, WireguardCmd};
use nix::sched;

use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};

pub fn join_netns(fd: RawFd) -> NetavarkResult<()> {
    match sched::setns(fd, sched::CloneFlags::CLONE_NEWNET) {
        Ok(_) => Ok(()),
        Err(e) => Err(NetavarkError::wrap(
            "setns",
            NetavarkError::Io(io::Error::from(e)),
        )),
    }
}

#[macro_export]
macro_rules! exec_netns {
    ($host:expr, $netns:expr, $result:ident, $exec:expr) => {};
}

/// wrap any result into a NetavarkError and add the given msg
macro_rules! wrap {
    ($result:expr, $msg:expr) => {
        $result.map_err(|err| NetavarkError::wrap($msg, err.into()))
    };
}

/// get the function name of the currently executed function
/// taken from https://stackoverflow.com/a/63904992
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);

        // Find and cut the rest of the path
        match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        }
    }};
}

// helper macros
macro_rules! expect_netlink_result {
    ($result:expr, $count:expr) => {
        if $result.len() != $count {
            return Err(NetavarkError::msg(format!(
                "{}: unexpected netlink result (got {} result(s), want {})",
                function!(),
                $result.len(),
                $count
            )));
        }
    };
}

pub trait NetlinkSocket {
    fn send<T>(&mut self, msg: T, flags: u16, family: Option<u16>) -> NetavarkResult<()>
    where
        T: NetlinkSerializable + std::fmt::Debug + Into<NetlinkPayload<T>>,
    {
        let mut nlmsg = NetlinkMessage::from(msg);
        nlmsg.header.flags = NLM_F_REQUEST | flags;
        nlmsg.header.sequence_number = self.increase_sequence_number();
        nlmsg.finalize();

        if let Some(family) = family {
            nlmsg.header.message_type = family;
        }

        //  buffer size for netlink messages, see NLMSG_GOODSIZE in the kernel
        let mut buffer = [0; 8192];
        let socket = self.get_socket();

        nlmsg.serialize(&mut buffer[..]);

        trace!("sending GenlCtrl netlink msg: {:?}", nlmsg);
        socket.send(&buffer[..nlmsg.buffer_len()], 0)?;
        Ok(())
    }

    fn get_socket(&self) -> &netlink_sys::Socket;
    fn get_sequence_number(&self) -> u32;
    fn increase_sequence_number(&mut self) -> u32;

    fn recv<T>(&mut self, multi: bool) -> NetavarkResult<Vec<T>>
    where
        T: std::fmt::Debug + NetlinkDeserializable,
    {
        let mut offset = 0;
        let mut result = Vec::new();

        // if multi is set we expect a multi part message
        let socket = self.get_socket();
        let sequence_number = self.get_sequence_number();
        //  buffer size for netlink messages, see NLMSG_GOODSIZE in the kernel
        let mut buffer = [0; 8192];
        loop {
            let size = wrap!(socket.recv(&mut &mut buffer[..], 0), "recv from netlink")?;

            loop {
                let bytes = &buffer[offset..];
                let rx_packet: NetlinkMessage<T> =
                    NetlinkMessage::deserialize(bytes).map_err(|e| {
                        NetavarkError::Message(format!(
                            "failed to deserialize netlink message: {}",
                            e,
                        ))
                    })?;
                trace!("read netlink packet: {:?}", rx_packet);

                if rx_packet.header.sequence_number != sequence_number {
                    return Err(NetavarkError::msg(format!(
                        "netlink: sequence_number out of sync (got {}, want {})",
                        rx_packet.header.sequence_number, sequence_number,
                    )));
                }

                match rx_packet.payload {
                    NetlinkPayload::Done => return Ok(result),
                    NetlinkPayload::Error(e) | NetlinkPayload::Ack(e) => {
                        if e.code != 0 {
                            return Err(e.into());
                        }
                        return Ok(result);
                    }
                    NetlinkPayload::Noop => {
                        return Err(NetavarkError::msg(
                            "unimplemented netlink message type NOOP",
                        ))
                    }
                    NetlinkPayload::Overrun(_) => {
                        return Err(NetavarkError::msg(
                            "unimplemented netlink message type OVERRUN",
                        ))
                    }
                    NetlinkPayload::InnerMessage(msg) => {
                        result.push(msg);
                        if !multi {
                            return Ok(result);
                        }
                    }
                    _ => {
                        // The NetlinkPayload could have new members that are not yet covered by
                        // netavark. This is because of https://github.com/rust-netlink/netlink-packet-core/commit/53a4c4ecfec60e1f26ad8b6aaa62abc7b112df50
                        return Err(NetavarkError::msg("unimplemented netlink message type"));
                    }
                };

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }
    }
}

pub struct GenericSocket {
    socket: netlink_sys::Socket,
    sequence_number: u32,
    wireguard_family: Option<u16>,
}

impl NetlinkSocket for GenericSocket {
    fn get_socket(&self) -> &netlink_sys::Socket {
        &self.socket
    }

    fn get_sequence_number(&self) -> u32 {
        self.sequence_number
    }

    fn increase_sequence_number(&mut self) -> u32 {
        self.sequence_number += 1;
        self.sequence_number
    }
}

impl GenericSocket {
    pub fn new() -> NetavarkResult<GenericSocket> {
        let mut socket = wrap!(netlink_sys::Socket::new(NETLINK_GENERIC), "open")?;
        let kernel_addr = &netlink_sys::SocketAddr::new(0, 0);
        wrap!(socket.bind_auto(), "bind")?;
        wrap!(socket.connect(kernel_addr), "connect")?;

        Ok(GenericSocket {
            socket,
            sequence_number: 0,
            wireguard_family: None,
        })
    }

    pub fn set_wireguard_device(&mut self, nlas: Vec<WgDeviceAttrs>) -> NetavarkResult<()> {
        let msg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
            cmd: WireguardCmd::SetDevice,
            nlas,
        });
        let result = self.make_wireguard_request(msg, NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    fn query_family_id(&mut self, family_name: &'static str) -> NetavarkResult<u16> {
        let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName(family_name.to_owned())],
        });
        let mut result = self.make_ctrl_request(genlmsg, true, NLM_F_ACK)?;
        expect_netlink_result!(result, 1);
        let result: GenlMessage<GenlCtrl> = result.remove(0);
        let mut family: Option<u16> = None;
        for nla in result.payload.nlas {
            if let GenlCtrlAttrs::FamilyId(m) = nla {
                family = Some(m)
            }
        }
        match family {
            Some(fam) => Ok(fam),
            None => Err(NetavarkError::msg(
                "Unable to resolve netlink family id for WireGuard API packets",
            )),
        }
    }

    fn make_ctrl_request(
        &mut self,
        msg: GenlMessage<GenlCtrl>,
        multi: bool,
        flags: u16,
    ) -> NetavarkResult<Vec<GenlMessage<GenlCtrl>>> {
        match self.send(msg, flags, None) {
            Ok(_) => (),
            Err(e) => panic!("Error sending packing via netlink API: {}", e),
        };

        self.recv(multi)
    }

    fn make_wireguard_request(
        &mut self,
        msg: GenlMessage<Wireguard>,
        flags: u16,
    ) -> NetavarkResult<Vec<GenlMessage<Wireguard>>> {
        if self.wireguard_family.is_none() {
            let family = self
                .query_family_id("wireguard")
                .expect("Could not resolve family_id for WireGuard netlink API");
            trace!("WireGuard family ID is: {:?}", family);
            self.wireguard_family = Some(family);
        }
        match self.send(msg, flags, self.wireguard_family) {
            Ok(_) => (),
            Err(e) => panic!("Error sending packing via netlink API: {}", e),
        };
        self.recv(flags & NLM_F_DUMP == NLM_F_DUMP)
    }
}
